# Silent Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make updates install silently with no installer window — user clicks "Restart to update", app closes, Inno Setup installs in background, new version launches automatically.

**Architecture:** Pass `/VERYSILENT /SUPPRESSMSGBOXES` to the Inno Setup `.exe` installer, remove `skipifsilent` from the `[Run]` entry in both `.iss` files so the app relaunches post-install, flip `update_auto_download_zip` default to `True` so the installer is pre-downloaded, and update UI copy from "Install now" to "Restart to update". The `SidebarUpdateCard` gains `downloaded`/`downloading`/`progressPercent` props to show an accurate state during background download.

**Tech Stack:** Python 3 (pytest for tests), Inno Setup 6 `.iss` scripts, React + TypeScript (Tauri), lucide-react icons.

**Spec:** `docs/superpowers/specs/2026-04-05-silent-update-design.md`

---

## File Map

| File | What changes |
|---|---|
| `shared/update_runtime.py` | `_launch_installer_exe()` gets silent flags; `_auto_download()` fallback `→ True` |
| `app/core/config.py` | `update_auto_download_zip` field default + `from_dict()` coercion `→ True` |
| `installer/MonClubAccess.iss` | Remove `skipifsilent` from `[Run]` line 77 |
| `installer/MonClubTV.iss` | Remove `skipifsilent` from `[Run]` line 76 |
| `tauri-ui/src/pages/UpdatePage.tsx` | "Install now" → "Restart to update" on line 295 |
| `tauri-ui/src/tv/pages/TvUpdatePage.tsx` | "Install now" → "Restart to update" on line 266 |
| `tauri-ui/src/components/SidebarUpdateCard.tsx` | Add 3 new props; update sub-label copy per state |
| `tauri-ui/src/layouts/MainLayout.tsx` | Extract + pass `downloaded`/`downloading`/`progressPercent` to `SidebarUpdateCard` |
| `tests/test_silent_update.py` | New — unit tests for Python changes |

---

## Task 1: Python — silent installer launch + auto-download default

**Files:**
- Modify: `shared/update_runtime.py:123-132` (`_launch_installer_exe`), `shared/update_runtime.py:280` (`_auto_download`)
- Modify: `app/core/config.py:140` (field default), `app/core/config.py:463` (`from_dict` coercion)
- Create: `tests/test_silent_update.py`

---

- [ ] **Step 1: Write the failing tests**

Create `tests/test_silent_update.py`:

```python
"""Tests for silent update behaviour."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# _launch_installer_exe
# ---------------------------------------------------------------------------

def _call_launch(silent: bool, exe_path: str = r"C:\fake\setup.exe"):
    """Helper: call _launch_installer_exe and return the Popen call args."""
    from shared.update_runtime import _launch_installer_exe
    with patch("shared.update_runtime.subprocess.Popen") as mock_popen:
        _launch_installer_exe(Path(exe_path), silent=silent)
        return mock_popen.call_args


def test_launch_installer_exe_silent_adds_flags():
    """Default silent=True must pass /VERYSILENT and /SUPPRESSMSGBOXES."""
    call = _call_launch(silent=True)
    cmd = call[0][0]          # first positional arg = the command list
    assert "/VERYSILENT" in cmd
    assert "/SUPPRESSMSGBOXES" in cmd


def test_launch_installer_exe_not_silent_omits_flags():
    """silent=False must NOT pass silent flags."""
    call = _call_launch(silent=False)
    cmd = call[0][0]
    assert "/VERYSILENT" not in cmd
    assert "/SUPPRESSMSGBOXES" not in cmd


def test_launch_installer_exe_default_is_silent():
    """Calling _launch_installer_exe without silent kwarg must be silent."""
    from shared.update_runtime import _launch_installer_exe
    with patch("shared.update_runtime.subprocess.Popen") as mock_popen:
        _launch_installer_exe(Path(r"C:\fake\setup.exe"))
        cmd = mock_popen.call_args[0][0]
    assert "/VERYSILENT" in cmd


# ---------------------------------------------------------------------------
# _auto_download fallback
# ---------------------------------------------------------------------------

def _make_manager(has_attr: bool, value: bool | None = None):
    """Build a minimal ComponentUpdateManager with a controlled cfg."""
    from shared.update_runtime import ComponentUpdateManager
    cfg = SimpleNamespace()
    if has_attr:
        cfg.update_auto_download_zip = value
    identity = MagicMock()
    identity.component_id = "access"
    identity.default_install_root_name = "MonClubAccess"
    identity.legacy_install_root_names = []
    identity.updater_exe_name = "MonClubAccessUpdater.exe"
    app = MagicMock()
    mgr = ComponentUpdateManager.__new__(ComponentUpdateManager)
    mgr.cfg = cfg
    return mgr


def test_auto_download_fallback_is_true_when_attr_missing():
    """When cfg has no update_auto_download_zip, default must be True."""
    mgr = _make_manager(has_attr=False)
    assert mgr._auto_download() is True


def test_auto_download_explicit_false_is_respected():
    """Operator can still disable auto-download by setting it explicitly."""
    mgr = _make_manager(has_attr=True, value=False)
    assert mgr._auto_download() is False


def test_auto_download_explicit_true_is_respected():
    mgr = _make_manager(has_attr=True, value=True)
    assert mgr._auto_download() is True


# ---------------------------------------------------------------------------
# AppConfig defaults
# ---------------------------------------------------------------------------

def test_appconfig_field_default_is_true():
    """AppConfig() with no args must have update_auto_download_zip = True."""
    from app.core.config import AppConfig
    cfg = AppConfig()
    assert cfg.update_auto_download_zip is True


def test_appconfig_from_dict_empty_defaults_to_true():
    """AppConfig.from_dict({}) must produce update_auto_download_zip = True."""
    from app.core.config import AppConfig
    cfg = AppConfig.from_dict({})
    assert cfg.update_auto_download_zip is True


def test_appconfig_from_dict_explicit_false_is_respected():
    """Operator config with update_auto_download_zip=false must be False."""
    from app.core.config import AppConfig
    cfg = AppConfig.from_dict({"update_auto_download_zip": False})
    assert cfg.update_auto_download_zip is False
```

- [ ] **Step 2: Run tests — verify they all FAIL**

> **Python path note:** Run from the repo root (`C:\Users\mohaa\Desktop\monclub_access_python`). pytest sets the rootdir automatically and adds it to `sys.path`, making `shared` and `app` importable without any extra config. Do not `cd` into the `tests/` folder.

```bash
cd /c/Users/mohaa/Desktop/monclub_access_python
python -m pytest tests/test_silent_update.py -v
```

Expected: multiple failures. `_launch_installer_exe` has no `silent` param yet; `_auto_download` returns `False` fallback; `AppConfig` defaults to `False`.

---

- [ ] **Step 3: Edit `shared/update_runtime.py` — `_launch_installer_exe`**

Replace lines 123–132 (the function body):

```python
# BEFORE
def _launch_installer_exe(exe_path: Path) -> None:
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    subprocess.Popen(
        [str(exe_path)],
        cwd=str(exe_path.parent),
        close_fds=True,
        creationflags=creationflags,
    )

# AFTER
def _launch_installer_exe(exe_path: Path, *, silent: bool = True) -> None:
    cmd = [str(exe_path)]
    if silent:
        cmd += ["/VERYSILENT", "/SUPPRESSMSGBOXES"]
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    subprocess.Popen(
        cmd,
        cwd=str(exe_path.parent),
        close_fds=True,
        creationflags=creationflags,
    )
```

---

- [ ] **Step 4: Edit `shared/update_runtime.py` — `_auto_download` fallback**

Replace line 280:

```python
# BEFORE
return bool(getattr(self.cfg, "update_auto_download_zip", False))

# AFTER
return bool(getattr(self.cfg, "update_auto_download_zip", True))
```

---

- [ ] **Step 5: Edit `app/core/config.py` — field declaration (line 140)**

```python
# BEFORE
update_auto_download_zip: bool = False

# AFTER
update_auto_download_zip: bool = True
```

---

- [ ] **Step 6: Edit `app/core/config.py` — `from_dict` coercion (line 463)**

```python
# BEFORE
cfg.update_auto_download_zip = _ensure_bool(getattr(cfg, "update_auto_download_zip", False), False)

# AFTER
cfg.update_auto_download_zip = _ensure_bool(getattr(cfg, "update_auto_download_zip", True), True)
```

---

- [ ] **Step 7: Run tests — verify they all PASS**

```bash
cd /c/Users/mohaa/Desktop/monclub_access_python
python -m pytest tests/test_silent_update.py -v
```

Expected: all 9 tests PASS.

---

- [ ] **Step 8: Commit**

```bash
git add shared/update_runtime.py app/core/config.py tests/test_silent_update.py
git commit -m "feat: silent installer launch + flip auto-download default to True"
```

---

## Task 2: Inno Setup — remove `skipifsilent` from both `.iss` files

**Files:**
- Modify: `installer/MonClubAccess.iss:77`
- Modify: `installer/MonClubTV.iss:76`

---

- [ ] **Step 1: Edit `installer/MonClubAccess.iss` line 77**

```ini
; BEFORE
Filename: "{app}\current\{#MainExe}"; Description: "Launch MonClub Access"; Flags: nowait postinstall skipifsilent

; AFTER
Filename: "{app}\current\{#MainExe}"; Description: "Launch MonClub Access"; Flags: nowait postinstall
```

---

- [ ] **Step 2: Edit `installer/MonClubTV.iss` line 76**

```ini
; BEFORE
Filename: "{app}\current\{#MainExe}"; Description: "Launch MonClub TV"; Flags: nowait postinstall skipifsilent

; AFTER
Filename: "{app}\current\{#MainExe}"; Description: "Launch MonClub TV"; Flags: nowait postinstall
```

---

- [ ] **Step 3: Verify the change with grep**

```bash
grep -n "skipifsilent" installer/MonClubAccess.iss installer/MonClubTV.iss
```

Expected: no output (zero matches).

---

- [ ] **Step 4: Commit**

```bash
git add installer/MonClubAccess.iss installer/MonClubTV.iss
git commit -m "feat: remove skipifsilent so app relaunches after silent install"
```

---

## Task 3: Tauri — rename "Install now" button copy

**Files:**
- Modify: `tauri-ui/src/pages/UpdatePage.tsx:295`
- Modify: `tauri-ui/src/tv/pages/TvUpdatePage.tsx:266`

---

- [ ] **Step 1: Edit `tauri-ui/src/pages/UpdatePage.tsx` line 295**

```tsx
{/* BEFORE */}
Install now

{/* AFTER */}
Restart to update
```

The surrounding context (do not change this):
```tsx
<Button
  className="gap-2 flex-1 bg-emerald-600 hover:bg-emerald-700 text-white"
  onClick={handleInstall}
  disabled={installing}
>
  {installing
    ? <Loader2 className="h-4 w-4 animate-spin" />
    : <Zap className="h-4 w-4" />
  }
  Restart to update   {/* ← changed */}
</Button>
```

---

- [ ] **Step 2: Edit `tauri-ui/src/tv/pages/TvUpdatePage.tsx` line 266**

```tsx
{/* BEFORE */}
Install now

{/* AFTER */}
Restart to update
```

The surrounding context (do not change this):
```tsx
<Button
  className="gap-2 flex-1 bg-emerald-600 hover:bg-emerald-700 text-white"
  onClick={handleInstall}
  disabled={installing}
>
  {installing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
  Restart to update   {/* ← changed */}
</Button>
```

---

- [ ] **Step 3: Verify no "Install now" remains in update pages**

```bash
grep -n "Install now" tauri-ui/src/pages/UpdatePage.tsx tauri-ui/src/tv/pages/TvUpdatePage.tsx
```

Expected: no output.

---

- [ ] **Step 4: Commit**

```bash
git add tauri-ui/src/pages/UpdatePage.tsx tauri-ui/src/tv/pages/TvUpdatePage.tsx
git commit -m "feat: rename Install now to Restart to update in both update pages"
```

---

## Task 4: `SidebarUpdateCard` — download-aware props and copy

**Files:**
- Modify: `tauri-ui/src/components/SidebarUpdateCard.tsx`

The card currently shows "Install now" as soon as `updateAvailable=true`, even while the file is still downloading. This task adds three new props (`downloaded`, `downloading`, `progressPercent`) and updates the sub-label and collapsed-mode icon to reflect the real state.

---

- [ ] **Step 1: Replace the full file content**

Before replacing, confirm the current file starts with this props interface (so you know you're on the right version):

```tsx
// Current interface at the top of SidebarUpdateCard.tsx — should look like this:
interface SidebarUpdateCardProps {
  updateAvailable: boolean;
  latestVersion?: string | null;
  latestCodename?: string | null;
  sidebarOpen: boolean;
  onClick: () => void;
}
```

If it matches, proceed. Replace the entire file content with:

```tsx
import { ArrowRight, Download, Loader2, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import Lottie from "lottie-react";
import catAnimation from "@/assets/animations/cat-playing.json";


interface SidebarUpdateCardProps {
  updateAvailable: boolean;
  latestVersion?: string | null;
  latestCodename?: string | null;
  sidebarOpen: boolean;
  onClick: () => void;
  // New props — reflect background download state
  downloaded: boolean;
  downloading: boolean;
  progressPercent?: number | null;
}

export function SidebarUpdateCard({
  updateAvailable,
  latestVersion,
  latestCodename,
  sidebarOpen,
  onClick,
  downloaded,
  downloading,
  progressPercent,
}: SidebarUpdateCardProps) {
  if (!updateAvailable) return null;

  // Sub-label text changes based on download state
  const subLabel = downloading
    ? progressPercent != null
      ? `Downloading... ${progressPercent}%`
      : "Downloading..."
    : downloaded
    ? "Restart to update"
    : "Download update";

  return (
    <div className="shrink-0 px-3 pb-3">
      {sidebarOpen ? (
        <button
          onClick={onClick}
          className="group relative w-full overflow-hidden rounded-xl bg-card border border-border/50 text-left transition-all hover:border-primary/50 hover:shadow-[0_0_20px_-5px_hsl(var(--primary)/0.3)]"
        >
          {/* Subtle animated background gradient */}
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50 group-hover:opacity-100 transition-opacity duration-500" />

          {/* Top border glow */}
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/50 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

          {/* Lottie Animation Header */}
          <div className="relative h-[88px] w-full bg-primary/[0.04] overflow-hidden flex items-center justify-center border-b border-border/40">
            <Lottie
              animationData={catAnimation}
              loop={true}
              className="absolute w-[140px] h-[140px] pointer-events-none"
            />
          </div>

          <div className="relative p-3.5">
            <div className="flex items-start justify-between mb-2.5">
              <div className="flex items-center gap-2">
                <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary ring-1 ring-primary/25 group-hover:bg-primary/20 transition-colors">
                  <Sparkles className="h-3.5 w-3.5" />
                </div>
                <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground group-hover:text-primary transition-colors">
                  Update Ready
                </span>
              </div>
              <span className="flex h-2 w-2 mt-1 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
              </span>
            </div>

            <div className="space-y-1">
              <div className="flex flex-wrap items-baseline gap-1.5">
                <span className="text-sm font-semibold tracking-tight text-foreground">
                  {latestVersion ? `Version ${latestVersion}` : "New version"}
                </span>
                {latestCodename && (
                  <span className="text-[11px] font-medium text-muted-foreground border border-border rounded-full px-1.5 py-0.5 bg-muted/50">
                    {latestCodename}
                  </span>
                )}
              </div>
              <p className="text-[12px] text-muted-foreground flex items-center gap-1 group-hover:text-foreground transition-colors">
                {downloading && <Loader2 className="h-3 w-3 animate-spin" />}
                {subLabel}
                {!downloading && (
                  <ArrowRight className="h-3 w-3 inline-block -translate-x-1 opacity-0 group-hover:translate-x-0 group-hover:opacity-100 transition-all duration-300" />
                )}
              </p>
            </div>
          </div>
        </button>
      ) : (
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              onClick={onClick}
              className="group relative flex h-10 w-full items-center justify-center overflow-hidden rounded-xl bg-card border border-border/50 hover:border-primary/50 transition-all hover:shadow-[0_0_15px_-5px_hsl(var(--primary)/0.3)]"
            >
              <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-opacity" />
              {downloading
                ? <Loader2 className="relative h-4 w-4 text-primary animate-spin" />
                : <Download className="relative h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
              }
              <span className="absolute top-1.5 right-1.5 flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-primary"></span>
              </span>
            </button>
          </TooltipTrigger>
          <TooltipContent side="right" className="font-medium text-[12px]">
            {downloading
              ? progressPercent != null ? `Downloading... ${progressPercent}%` : "Downloading..."
              : downloaded
              ? `Restart to update${latestVersion ? ` · v${latestVersion}` : ""}`
              : `Update available${latestVersion ? ` · v${latestVersion}` : ""}`
            }
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  );
}
```

---

- [ ] **Step 2: Verify TypeScript compiles (no new errors)**

```bash
cd /c/Users/mohaa/Desktop/monclub_access_python/tauri-ui
npx tsc --noEmit 2>&1 | head -30
```

Expected: errors only from `MainLayout.tsx` about the 3 missing required props (that's expected — Task 5 fixes them). No errors in `SidebarUpdateCard.tsx` itself.

---

- [ ] **Step 3: Commit**

```bash
git add tauri-ui/src/components/SidebarUpdateCard.tsx
git commit -m "feat: SidebarUpdateCard shows downloading state and Restart to update copy"
```

---

## Task 5: `MainLayout` — pass new props to `SidebarUpdateCard`

**Files:**
- Modify: `tauri-ui/src/layouts/MainLayout.tsx`

The `status?.updates` object already has `downloaded`, `downloading`, and `progressPercent` in the `UpdatesBlock` type — we just need to extract them and pass them through.

---

- [ ] **Step 1: Add three derived variables after line 69**

Current block (lines 67–69):
```tsx
const updateAvailable = status?.updates?.updateAvailable ?? false;
const latestVersion = (status?.updates as { latestVersion?: string | null })?.latestVersion ?? null;
const latestCodename = (status?.updates as { latestCodename?: string | null })?.latestCodename ?? null;
```

Replace with (add 3 new lines):
```tsx
const updateAvailable = status?.updates?.updateAvailable ?? false;
const latestVersion = (status?.updates as { latestVersion?: string | null })?.latestVersion ?? null;
const latestCodename = (status?.updates as { latestCodename?: string | null })?.latestCodename ?? null;
// No `as` cast needed below — downloaded/downloading/progressPercent are already
// typed directly on UpdatesBlock (tauri-ui/src/api/types.ts lines 54–57).
const updateDownloaded = status?.updates?.downloaded ?? false;
const updateDownloading = status?.updates?.downloading ?? false;
const updateProgressPercent = status?.updates?.progressPercent ?? null;
```

---

- [ ] **Step 2: Pass the new props to `SidebarUpdateCard` (lines 181–187)**

Current:
```tsx
<SidebarUpdateCard
  updateAvailable={updateAvailable}
  latestVersion={latestVersion}
  latestCodename={latestCodename}
  sidebarOpen={sidebarOpen}
  onClick={() => navigate("/update")}
/>
```

Replace with:
```tsx
<SidebarUpdateCard
  updateAvailable={updateAvailable}
  latestVersion={latestVersion}
  latestCodename={latestCodename}
  sidebarOpen={sidebarOpen}
  onClick={() => navigate("/update")}
  downloaded={updateDownloaded}
  downloading={updateDownloading}
  progressPercent={updateProgressPercent}
/>
```

---

- [ ] **Step 3: Verify TypeScript compiles with zero errors**

```bash
cd /c/Users/mohaa/Desktop/monclub_access_python/tauri-ui
npx tsc --noEmit 2>&1 | head -30
```

Expected: no output (zero errors).

---

- [ ] **Step 4: Commit**

```bash
git add tauri-ui/src/layouts/MainLayout.tsx
git commit -m "feat: pass download state props to SidebarUpdateCard from MainLayout"
```

---

## Final Verification

- [ ] **Run the full Python test suite**

```bash
cd /c/Users/mohaa/Desktop/monclub_access_python
python -m pytest tests/ -v
```

Expected: all existing tests pass plus all 9 new tests in `test_silent_update.py`.

- [ ] **Verify no "Install now" strings remain anywhere in update UI**

```bash
grep -rn "Install now" tauri-ui/src/pages/ tauri-ui/src/tv/pages/ tauri-ui/src/components/SidebarUpdateCard.tsx
```

Expected: no output.

- [ ] **Verify `skipifsilent` is gone from both `.iss` files**

```bash
grep -n "skipifsilent" installer/MonClubAccess.iss installer/MonClubTV.iss
```

Expected: no output.

- [ ] **Verify the two config.py changes are in place**

```bash
grep -n "update_auto_download_zip" app/core/config.py
```

Expected output (both `True`):
```
140:    update_auto_download_zip: bool = True
463:        cfg.update_auto_download_zip = _ensure_bool(getattr(cfg, "update_auto_download_zip", True), True)
```

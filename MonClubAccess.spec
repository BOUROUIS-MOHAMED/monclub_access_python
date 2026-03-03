# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None


def safe_collect_submodules(pkg: str):
    try:
        return collect_submodules(pkg)
    except Exception:
        return []


# IMPORTANT:
# Some PyInstaller executions do not define __file__ for spec namespace.
# Since build_release.ps1 sets CWD to repo root, we use Path.cwd().
ROOT = Path.cwd().resolve()

APP_ENTRY = str(ROOT / "app" / "main.py")
SDK_DIR = ROOT / "app" / "sdk"

# --------------------------
# App icon (Windows)
# --------------------------
APP_ICON = ROOT / "app" / "ui" / "assets" / "app.ico"
ICON_PATH = str(APP_ICON) if APP_ICON.exists() else None

# --------------------------
# Collect SDK DLLs
# They land under dist/<app>/_internal/sdk by default in PyInstaller 6.
# build_release.ps1 also copies them to dist/<app>/sdk for your resolver.
# --------------------------
binaries = []
if SDK_DIR.exists():
    for dll in SDK_DIR.glob("*.dll"):
        binaries.append((str(dll), "sdk"))

# --------------------------
# Data files (certifi)
# --------------------------
datas = []
try:
    datas += collect_data_files("certifi")
except Exception:
    pass

# --------------------------
# Hidden imports (defensive)
# - include your local packages too (tkinter apps often import pages dynamically)
# --------------------------
hiddenimports = []
hiddenimports += safe_collect_submodules("requests")
hiddenimports += safe_collect_submodules("urllib3")
hiddenimports += safe_collect_submodules("charset_normalizer")
hiddenimports += safe_collect_submodules("certifi")
hiddenimports += safe_collect_submodules("PIL")
hiddenimports += safe_collect_submodules("pystray")

hiddenimports += safe_collect_submodules("app")
hiddenimports += safe_collect_submodules("app.api")
hiddenimports += safe_collect_submodules("app.core")
hiddenimports += safe_collect_submodules("app.ui")
hiddenimports += safe_collect_submodules("app.ui.pages")
hiddenimports += safe_collect_submodules("app.ui.pages.popups")
hiddenimports += safe_collect_submodules("app.sdk")

a = Analysis(
    [APP_ENTRY],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="MonClubAccess",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # windowed
    disable_windowed_traceback=False,
    icon=ICON_PATH,  # <-- NEW: MonClubAccess.exe icon (requires .ico)
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="MonClubAccess",
)

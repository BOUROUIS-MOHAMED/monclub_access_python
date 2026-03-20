# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None


def safe_collect_submodules(pkg: str):
    try:
        return collect_submodules(pkg)
    except Exception:
        return []


ROOT = Path.cwd().resolve()

APP_ENTRY = str(ROOT / "tv" / "main.py")
APP_ICON = ROOT / "app" / "ui" / "assets" / "app.ico"
ICON_PATH = str(APP_ICON) if APP_ICON.exists() else None

datas = []
try:
    datas += collect_data_files("certifi")
except Exception:
    pass

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
hiddenimports += safe_collect_submodules("access")
hiddenimports += safe_collect_submodules("shared")
hiddenimports += safe_collect_submodules("shared.api")
hiddenimports += safe_collect_submodules("tv")

a = Analysis(
    [APP_ENTRY],
    pathex=[str(ROOT)],
    binaries=[],
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
    name="MonClubTV",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=ICON_PATH,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="MonClubTV",
)

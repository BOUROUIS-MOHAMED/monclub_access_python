# monclub_access_python/app/core/utils.py
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List


APP_NAME = "MonClub Access"

# Repo root in dev (your current behavior). In frozen, this is not used as data root.
LEGACY_APP_DIR = Path(__file__).resolve().parents[2]
LEGACY_DATA_DIR = LEGACY_APP_DIR / "data"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))  # PyInstaller sets sys.frozen


def runtime_base_dir() -> Path:
    """
    Directory where the running executable lives (frozen),
    or the repo root (dev).
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return LEGACY_APP_DIR


def runtime_internal_dir() -> Path:
    """
    PyInstaller 6+ onedir layout stores collected files under:
      <base>/_internal/...

    In dev, or older layouts, this may not exist.
    """
    base = runtime_base_dir()
    internal = base / "_internal"
    return internal if internal.exists() else base


def _candidate_data_roots() -> list[Path]:
    # Optional override (best for debugging / CI)
    override = (os.environ.get("MONCLUB_ACCESS_DATA_ROOT") or "").strip()
    if override:
        return [Path(override).expanduser().resolve()]

    roots: list[Path] = []
    if os.name == "nt":
        program_data = (os.environ.get("PROGRAMDATA") or r"C:\ProgramData").strip()
        local_appdata = (os.environ.get("LOCALAPPDATA") or "").strip()

        if program_data:
            roots.append(Path(program_data) / APP_NAME)

        if local_appdata:
            roots.append(Path(local_appdata) / APP_NAME)
        else:
            # last resort fallback
            roots.append(Path.home() / "AppData" / "Local" / APP_NAME)
    else:
        roots.append(Path.home() / f".{APP_NAME.lower().replace(' ', '_')}")

    return roots


def _pick_data_root() -> Path:
    """
    Pick a writable data root. Try ProgramData first, fallback to LocalAppData.
    """
    for root in _candidate_data_roots():
        try:
            (root / "data").mkdir(parents=True, exist_ok=True)
            return root
        except Exception:
            continue
    # If everything fails, return the last candidate (it will fail later with clearer logs)
    return _candidate_data_roots()[-1]


# --------------------------
# Public data paths
# --------------------------
DATA_ROOT = _pick_data_root()
DATA_DIR = DATA_ROOT / "data"
LOG_DIR = DATA_DIR / "logs"
CACHE_DIR = DATA_DIR / "cache"
IMAGES_CACHE_DIR = CACHE_DIR / "images"

BACKUP_DIR = DATA_ROOT / "backups"
VERSIONS_DIR = DATA_ROOT / "versions"

CONFIG_PATH = DATA_DIR / "config.json"
DB_PATH = DATA_DIR / "app.db"

# Phase 1 split-ready storage scaffolding. The live runtime still uses the
# legacy combined paths above until later migration phases move data into
# separate Access/TV databases and config files.
ACCESS_DATA_DIR = DATA_ROOT / "access"
TV_DATA_DIR = DATA_ROOT / "tv"
SHARED_DATA_DIR = DATA_ROOT / "shared"

ACCESS_LOG_DIR = ACCESS_DATA_DIR / "logs"
TV_LOG_DIR = TV_DATA_DIR / "logs"

ACCESS_CONFIG_PATH = ACCESS_DATA_DIR / "config.json"
TV_CONFIG_PATH = TV_DATA_DIR / "config.json"
SHARED_INSTALL_CONFIG_PATH = SHARED_DATA_DIR / "install.json"

ACCESS_DB_PATH = ACCESS_DATA_DIR / "access.db"
TV_DB_PATH = TV_DATA_DIR / "tv.db"


def _dir_has_any_files(p: Path) -> bool:
    try:
        if not p.exists():
            return False
        for x in p.rglob("*"):
            if x.is_file():
                return True
    except Exception:
        return False
    return False


def ensure_dirs() -> None:
    """
    Create required folders. Also migrates legacy ./data -> ProgramData/LocalAppData on first run.

    IMPORTANT:
    - We migrate BEFORE creating target subdirs, otherwise "exists()" checks for folders become true
      and we never copy legacy logs/images.
    """
    # Ensure root exists
    try:
        DATA_ROOT.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    _migrate_legacy_data_if_needed()

    for p in (
        DATA_DIR,
        LOG_DIR,
        CACHE_DIR,
        IMAGES_CACHE_DIR,
        BACKUP_DIR,
        VERSIONS_DIR,
        ACCESS_DATA_DIR,
        ACCESS_LOG_DIR,
        TV_DATA_DIR,
        TV_LOG_DIR,
        SHARED_DATA_DIR,
    ):
        try:
            p.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Let the caller/logging handle failure; we try our best here.
            pass


def _migrate_legacy_data_if_needed() -> None:
    """
    One-time migration: if old repo ./data exists and new ProgramData/LocalAppData files don't,
    copy app.db + config.json + cache/images + logs.

    This prevents "data loss" when you switch to ProgramData/LocalAppData.
    """
    try:
        if not LEGACY_DATA_DIR.exists():
            return

        # DB: copy only if new DB does not exist
        legacy_db = LEGACY_DATA_DIR / "app.db"
        if legacy_db.exists() and (not DB_PATH.exists()):
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(legacy_db), str(DB_PATH))

        # config: copy only if new config does not exist
        legacy_cfg = LEGACY_DATA_DIR / "config.json"
        if legacy_cfg.exists() and (not CONFIG_PATH.exists()):
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(legacy_cfg), str(CONFIG_PATH))

        # cache/images: copy if target has no files yet
        legacy_images = LEGACY_DATA_DIR / "cache" / "images"
        if legacy_images.exists() and (not _dir_has_any_files(IMAGES_CACHE_DIR)):
            IMAGES_CACHE_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copytree(str(legacy_images), str(IMAGES_CACHE_DIR), dirs_exist_ok=True)

        # logs: copy if target has no files yet
        legacy_logs = LEGACY_DATA_DIR / "logs"
        if legacy_logs.exists() and (not _dir_has_any_files(LOG_DIR)):
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copytree(str(legacy_logs), str(LOG_DIR), dirs_exist_ok=True)

    except Exception:
        # Never crash on migration
        return


def resolve_resource_path(path_str: str, *, must_exist: bool = True) -> Path:
    """
    Resolve a relative resource (like sdk/plcommpro.dll) against runtime base dir.

    Supports:
    - dev layout (repo root)
    - frozen onedir layout (PyInstaller 6+): <base>/_internal/...
    - stale absolute paths (handled by caller via fallback-by-name)

    Typical locations we support:
    - <base>/<relative>
    - <base>/sdk/<filename>
    - <base>/app/sdk/<filename> (dev)
    - <base>/_internal/sdk/<filename> (PyInstaller 6+)
    """
    s = (path_str or "").strip()
    if not s:
        raise FileNotFoundError("Empty resource path")

    p = Path(s)

    # absolute path
    if p.is_absolute():
        if (not must_exist) or p.exists():
            return p
        raise FileNotFoundError(f"Resource not found: {p}")

    base = runtime_base_dir()
    internal = runtime_internal_dir()

    # candidates:
    # 1) base/<given relative>
    # 2) base/sdk/<filename>
    # 3) base/app/sdk/<filename>    (dev layout)
    # 4) base/app/<given relative>  (dev if config says sdk/.. but actually under app/sdk)
    # 5) internal/<given relative>  (PyInstaller internal)
    # 6) internal/sdk/<filename>    (PyInstaller 6+ onedir)
    # 7) internal/app/sdk/<filename>
    # 8) internal/app/<given relative>
    candidates: list[Path] = [
        base / p,
        base / "sdk" / p.name,
        base / "app" / "sdk" / p.name,
        base / "app" / p,
        internal / p,
        internal / "sdk" / p.name,
        internal / "app" / "sdk" / p.name,
        internal / "app" / p,
    ]

    for c in candidates:
        if not must_exist:
            return c
        if c.exists():
            return c

    raise FileNotFoundError(f"Resource not found: '{s}' (base={base}, internal={internal})")


def add_windows_dll_search_paths() -> None:
    """
    For Python 3.8+ on Windows: add common SDK folders to DLL search path.
    This prevents random 'DLL not found' issues when frozen.

    IMPORTANT for PyInstaller 6+ onedir:
    - DLLs are typically under <base>/_internal/sdk
    """
    if os.name != "nt":
        return
    add_dir = getattr(os, "add_dll_directory", None)
    if not callable(add_dir):
        return

    base = runtime_base_dir()
    internal = runtime_internal_dir()

    # Add most relevant folders first
    candidates = [
        internal / "sdk",
        base / "sdk",
        base / "app" / "sdk",
        internal / "app" / "sdk",
        internal,  # sometimes dependent DLLs end up here
        base,
    ]

    for d in candidates:
        try:
            if d.exists():
                add_dir(str(d))
        except Exception:
            pass


def now_iso() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def encode_ansi(s: str) -> bytes:
    return s.encode("mbcs", errors="replace")


def decode_ansi(b: bytes) -> str:
    return b.decode("mbcs", errors="replace")


def mask_password(pwd: str) -> str:
    if not pwd:
        return ""
    return "*" * min(8, len(pwd))


def safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def from_b64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def to_hex(data: bytes) -> str:
    return data.hex()


def from_hex(s: str) -> bytes:
    return bytes.fromhex(s)


def parse_device_text(text: str) -> List[Dict[str, str]]:
    lines = [ln.strip() for ln in text.replace("\r", "").split("\n") if ln.strip()]
    if not lines:
        return []

    first = lines[0]
    rows: List[Dict[str, str]] = []

    if "=" in first and "\t" in first:
        for ln in lines:
            kv: Dict[str, str] = {}
            parts = [p for p in ln.split("\t") if "=" in p]
            for p in parts:
                k, v = p.split("=", 1)
                kv[k.strip()] = v.strip()
            if kv:
                rows.append(kv)
        return rows

    headers = [h.strip() for h in first.split(",")]
    for ln in lines[1:]:
        cols = [c.strip() for c in ln.split(",")]
        kv: Dict[str, str] = {}
        for i in range(min(len(headers), len(cols))):
            if headers[i]:
                kv[headers[i]] = cols[i]
        if kv:
            rows.append(kv)
    return rows


def dict_union_keys(rows: List[Dict[str, str]]) -> List[str]:
    seen: List[str] = []
    for r in rows:
        for k in r.keys():
            if k not in seen:
                seen.append(k)
    return seen


def load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

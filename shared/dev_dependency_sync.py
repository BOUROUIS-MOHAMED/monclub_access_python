from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable


STAMP_FILE_NAME = ".monclub_requirements.sha256"


def requirements_digest(requirements_path: Path) -> str:
    return hashlib.sha256(requirements_path.read_bytes()).hexdigest()


def _venv_root_from_python(python_executable: Path) -> Path | None:
    try:
        resolved = python_executable.resolve()
    except Exception:
        resolved = python_executable
    venv_root = resolved.parent.parent
    if (venv_root / "pyvenv.cfg").exists():
        return venv_root
    return None


def ensure_local_requirements_synced(
    *,
    repo_root: Path | None = None,
    python_executable: Path | None = None,
    frozen: bool | None = None,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> bool:
    if frozen is None:
        frozen = bool(getattr(sys, "frozen", False))
    if frozen:
        return False
    if os.environ.get("MONCLUB_SKIP_REQUIREMENTS_SYNC") == "1":
        return False

    repo_root = Path(repo_root or Path(__file__).resolve().parents[1])
    requirements_path = repo_root / "requirements.txt"
    if not requirements_path.exists():
        return False

    python_executable = Path(python_executable or sys.executable)
    venv_root = _venv_root_from_python(python_executable)
    if venv_root is None:
        return False

    current_digest = requirements_digest(requirements_path)
    stamp_path = venv_root / STAMP_FILE_NAME
    previous_digest = ""
    try:
        previous_digest = stamp_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        previous_digest = ""

    if previous_digest == current_digest:
        return False

    print("[bootstrap] requirements.txt changed; syncing local dependencies...")
    result = runner(
        [str(python_executable), "-m", "pip", "install", "-r", str(requirements_path)],
        cwd=str(repo_root),
        check=False,
    )
    if int(getattr(result, "returncode", 1)) != 0:
        raise RuntimeError(
            "Dependency sync failed on this PC. "
            "Run `.venv\\Scripts\\python.exe -m pip install -r requirements.txt` and retry."
        )

    stamp_path.write_text(current_digest + "\n", encoding="utf-8")
    return True


__all__ = [
    "STAMP_FILE_NAME",
    "ensure_local_requirements_synced",
    "requirements_digest",
]

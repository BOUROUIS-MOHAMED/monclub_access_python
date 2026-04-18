from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest


def test_ensure_local_requirements_synced_runs_pip_and_writes_stamp(tmp_path: Path) -> None:
    from shared.dev_dependency_sync import ensure_local_requirements_synced

    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    requirements = repo_root / "requirements.txt"
    requirements.write_text("comtypes>=1.4\n", encoding="utf-8")

    venv_root = repo_root / ".venv"
    scripts_dir = venv_root / "Scripts"
    scripts_dir.mkdir(parents=True)
    python_exe = scripts_dir / "python.exe"
    python_exe.write_text("", encoding="utf-8")
    (venv_root / "pyvenv.cfg").write_text("home = C:\\Python311\n", encoding="utf-8")

    calls: list[tuple[list[str], str]] = []

    def fake_runner(args: list[str], *, cwd: str, check: bool) -> SimpleNamespace:
        calls.append((args, cwd))
        return SimpleNamespace(returncode=0)

    changed = ensure_local_requirements_synced(
        repo_root=repo_root,
        python_executable=python_exe,
        frozen=False,
        runner=fake_runner,
    )

    assert changed is True
    assert calls == [
        ([str(python_exe), "-m", "pip", "install", "-r", str(requirements)], str(repo_root))
    ]
    stamp_path = venv_root / ".monclub_requirements.sha256"
    assert stamp_path.exists()
    assert stamp_path.read_text(encoding="utf-8").strip()


def test_ensure_local_requirements_synced_skips_when_stamp_matches(tmp_path: Path) -> None:
    from shared.dev_dependency_sync import ensure_local_requirements_synced, requirements_digest

    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    requirements = repo_root / "requirements.txt"
    requirements.write_text("comtypes>=1.4\n", encoding="utf-8")

    venv_root = repo_root / ".venv"
    scripts_dir = venv_root / "Scripts"
    scripts_dir.mkdir(parents=True)
    python_exe = scripts_dir / "python.exe"
    python_exe.write_text("", encoding="utf-8")
    (venv_root / "pyvenv.cfg").write_text("home = C:\\Python311\n", encoding="utf-8")
    (venv_root / ".monclub_requirements.sha256").write_text(
        requirements_digest(requirements),
        encoding="utf-8",
    )

    def fake_runner(args: list[str], *, cwd: str, check: bool) -> SimpleNamespace:
        raise AssertionError("pip should not run when requirements hash matches")

    changed = ensure_local_requirements_synced(
        repo_root=repo_root,
        python_executable=python_exe,
        frozen=False,
        runner=fake_runner,
    )

    assert changed is False


def test_ensure_local_requirements_synced_raises_helpful_error_on_failure(tmp_path: Path) -> None:
    from shared.dev_dependency_sync import ensure_local_requirements_synced

    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    requirements = repo_root / "requirements.txt"
    requirements.write_text("comtypes>=1.4\n", encoding="utf-8")

    venv_root = repo_root / ".venv"
    scripts_dir = venv_root / "Scripts"
    scripts_dir.mkdir(parents=True)
    python_exe = scripts_dir / "python.exe"
    python_exe.write_text("", encoding="utf-8")
    (venv_root / "pyvenv.cfg").write_text("home = C:\\Python311\n", encoding="utf-8")

    def fake_runner(args: list[str], *, cwd: str, check: bool) -> SimpleNamespace:
        return SimpleNamespace(returncode=1)

    with pytest.raises(RuntimeError, match="pip install -r requirements.txt"):
        ensure_local_requirements_synced(
            repo_root=repo_root,
            python_executable=python_exe,
            frozen=False,
            runner=fake_runner,
        )

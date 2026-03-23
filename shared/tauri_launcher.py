"""Shared Tauri launcher helpers for Access and TV desktop shells."""

from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path
from typing import Optional


def _is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Return True if *port* is already bound on *host*."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        try:
            s.connect((host, port))
            return True
        except (ConnectionRefusedError, OSError):
            return False

from shared.runtime_support import runtime_base_dir


def launch_tauri_ui(
    *,
    role: str,
    api_port: int,
    logger,
    existing_process: Optional[subprocess.Popen] = None,
) -> Optional[subprocess.Popen]:
    """Launch the shared Tauri UI binary in the requested shell mode."""

    if existing_process and existing_process.poll() is None:
        logger.debug("[Tauri:%s] Already running (pid=%s)", role, existing_process.pid)
        return existing_process

    normalized_role = str(role or "access").strip().lower() or "access"

    runtime_base = runtime_base_dir()
    bundled_candidates = []
    if normalized_role == "tv":
        bundled_candidates = [
            runtime_base / "ui" / "monclub-tv-ui.exe",
            runtime_base / "ui" / "monclub-access-ui.exe",
        ]
    else:
        bundled_candidates = [
            runtime_base / "ui" / "monclub-access-ui.exe",
            runtime_base / "ui" / "monclub-tv-ui.exe",
        ]

    repo_base = Path(__file__).resolve().parent.parent
    tauri_dir = repo_base / "tauri-ui"
    is_dev = (tauri_dir / "node_modules").is_dir()

    env = os.environ.copy()
    env["MONCLUB_DESKTOP_ROLE"] = normalized_role
    env["MONCLUB_LOCAL_API_PORT"] = str(int(api_port))

    cargo_bin = Path.home() / ".cargo" / "bin"
    if cargo_bin.is_dir():
        env["PATH"] = str(cargo_bin) + os.pathsep + env.get("PATH", "")

    for bundled_exe in bundled_candidates:
        if not bundled_exe.exists():
            continue
        try:
            proc = subprocess.Popen(
                [str(bundled_exe)],
                cwd=str(bundled_exe.parent),
                env=env,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            logger.info("[Tauri:%s] Launched bundled UI exe: %s (pid=%s)", role, bundled_exe, proc.pid)
            return proc
        except Exception as exc:
            logger.warning("[Tauri:%s] Failed to launch bundled UI exe %s: %s", role, bundled_exe, exc)

    if is_dev and (tauri_dir / "package.json").exists():
        npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
        vite_port = 1420
        vite_already_running = _is_port_in_use(vite_port)
        if vite_already_running:
            # Vite dev server is already up (started by the other app instance).
            # Run cargo directly to open a second Tauri window without trying to
            # restart Vite on the same port (which would fail with strictPort).
            cargo_cmd = "cargo.exe" if os.name == "nt" else "cargo"
            src_tauri_dir = tauri_dir / "src-tauri"
            try:
                proc = subprocess.Popen(
                    [cargo_cmd, "run", "--no-default-features", "--color", "always", "--"],
                    cwd=str(src_tauri_dir),
                    env=env,
                )
                logger.info("[Tauri:%s] Launched 'cargo run' (Vite already on :%d) (pid=%s)", role, vite_port, proc.pid)
                return proc
            except Exception as exc:
                logger.warning("[Tauri:%s] Failed to launch cargo run: %s", role, exc)
        else:
            try:
                proc = subprocess.Popen(
                    [npm_cmd, "run", "tauri", "dev"],
                    cwd=str(tauri_dir),
                    env=env,
                )
                logger.info("[Tauri:%s] Launched 'npm run tauri dev' (pid=%s)", role, proc.pid)
                return proc
            except Exception as exc:
                logger.warning("[Tauri:%s] Failed to launch npm tauri dev: %s", role, exc)

    built_candidates = []
    component_shell_dir = tauri_dir / "component-shells" / ("MonClubTV" if normalized_role == "tv" else "MonClubAccess")
    if normalized_role == "tv":
        built_candidates.extend(
            [
                component_shell_dir / "monclub-tv-ui.exe",
                component_shell_dir / "monclub-access-ui.exe",
            ]
        )
    else:
        built_candidates.extend(
            [
                component_shell_dir / "monclub-access-ui.exe",
                component_shell_dir / "monclub-tv-ui.exe",
            ]
        )
    for profile in ("release", "debug"):
        if normalized_role == "tv":
            built_candidates.extend(
                [
                    tauri_dir / "src-tauri" / "target" / profile / "monclub-tv-ui.exe",
                    tauri_dir / "src-tauri" / "target" / profile / "monclub-access-ui.exe",
                ]
            )
        else:
            built_candidates.extend(
                [
                    tauri_dir / "src-tauri" / "target" / profile / "monclub-access-ui.exe",
                    tauri_dir / "src-tauri" / "target" / profile / "monclub-tv-ui.exe",
                ]
            )

    for exe in built_candidates:
        if not exe.exists():
            continue
        try:
            proc = subprocess.Popen(
                [str(exe)],
                cwd=str(tauri_dir),
                env=env,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            logger.info("[Tauri:%s] Launched built exe: %s (pid=%s)", role, exe, proc.pid)
            return proc
        except Exception as exc:
            logger.warning("[Tauri:%s] Failed to launch exe %s: %s", role, exe, exc)

    logger.warning("[Tauri:%s] No Tauri UI found.", role)
    return None


def kill_tauri_ui(process: Optional[subprocess.Popen], *, role: str, logger) -> None:
    if not process:
        return
    try:
        if process.poll() is None:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                    capture_output=True,
                    timeout=5,
                )
            except Exception:
                process.kill()
            logger.info("[Tauri:%s] UI process terminated.", role)
    except Exception as exc:
        logger.debug("[Tauri:%s] Kill failed: %s", role, exc)

"""Cross-process single-instance guard helpers."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from shared.desktop_paths import get_desktop_path_layout

_NAME_SAFE_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")


class SingleInstanceAlreadyRunning(RuntimeError):
    """Raised when another process already owns the component singleton."""


def _default_lock_dir(component_id: str) -> Path:
    layout = get_desktop_path_layout()
    return layout.shared_data_dir / "locks" / str(component_id or "app").strip().lower()


def _normalized_component_id(component_id: str) -> str:
    normalized = _NAME_SAFE_CHARS.sub("-", str(component_id or "").strip().lower()).strip("-")
    if not normalized:
        raise ValueError("component_id must not be empty")
    return normalized


def _resolve_lock_dir(component_id: str, lock_dir: Path | None) -> Path:
    root = Path(lock_dir) if lock_dir is not None else _default_lock_dir(component_id)
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def _build_windows_mutex_name(component_id: str, lock_root: Path) -> str:
    normalized_component = _normalized_component_id(component_id)
    fingerprint = hashlib.sha256(
        f"{normalized_component}|{lock_root.as_posix()}".encode("utf-8")
    ).hexdigest()
    return f"Local\\MonClubAccess.{normalized_component}.{fingerprint}"


@dataclass
class SingleInstanceGuard:
    """Owns a platform-specific singleton handle until released."""

    _release_callback: Callable[[], None] | None

    def release(self) -> None:
        callback = self._release_callback
        if callback is None:
            return
        self._release_callback = None
        callback()

    def __enter__(self) -> "SingleInstanceGuard":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


def _acquire_windows_mutex(component_id: str, lock_root: Path) -> SingleInstanceGuard:
    import ctypes
    from ctypes import wintypes

    error_already_exists = 183
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    mutex_name = _build_windows_mutex_name(component_id=component_id, lock_root=lock_root)
    handle = kernel32.CreateMutexW(None, False, mutex_name)
    if not handle:
        raise OSError(ctypes.get_last_error(), f"Failed to create mutex {mutex_name!r}")

    last_error = ctypes.get_last_error()
    if last_error == error_already_exists:
        kernel32.CloseHandle(handle)
        raise SingleInstanceAlreadyRunning(f"{component_id} is already running")

    def _release() -> None:
        if not kernel32.CloseHandle(handle):
            close_error = ctypes.get_last_error()
            raise OSError(close_error, f"Failed to close mutex {mutex_name!r}")

    return SingleInstanceGuard(_release_callback=_release)


def _acquire_posix_file_lock(component_id: str, lock_root: Path) -> SingleInstanceGuard:
    import fcntl

    normalized_component = _normalized_component_id(component_id)
    lock_path = lock_root / f"{normalized_component}.lock"
    handle = open(lock_path, "a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise SingleInstanceAlreadyRunning(f"{component_id} is already running") from exc

    try:
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
    except Exception:
        pass

    def _release() -> None:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    return SingleInstanceGuard(_release_callback=_release)


def acquire_single_instance_guard(
    component_id: str,
    lock_dir: Path | None = None,
) -> SingleInstanceGuard:
    """Acquire a per-component singleton guard for the current process."""

    lock_root = _resolve_lock_dir(component_id=component_id, lock_dir=lock_dir)
    if os.name == "nt":
        return _acquire_windows_mutex(component_id=component_id, lock_root=lock_root)
    return _acquire_posix_file_lock(component_id=component_id, lock_root=lock_root)


__all__ = [
    "SingleInstanceAlreadyRunning",
    "SingleInstanceGuard",
    "acquire_single_instance_guard",
]

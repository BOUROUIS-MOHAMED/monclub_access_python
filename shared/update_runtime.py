"""Shared component-aware update runtime used by Access and TV."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from shared.component_identity import DesktopComponentIdentity
from shared.desktop_paths import get_desktop_path_layout
from shared.runtime_support import is_frozen, runtime_base_dir


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    try:
        s = str(v).strip()
        return s if s else default
    except Exception:
        return default


def _lower(v: Any) -> str:
    return _safe_str(v, "").lower()


def _parse_json_file(p: Path) -> Dict[str, Any]:
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _semver_tuple(v: str) -> Optional[Tuple[int, int, int]]:
    """Parse 'x.y.z' or 'x.y.z codename' → (x, y, z). Returns None if invalid."""
    if not v:
        return None
    numeric = v.strip().split()[0]
    parts = numeric.split(".")
    if len(parts) < 3:
        return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None


def _is_version_outdated(current: str, latest: str) -> bool:
    """Return True if current < latest (semver comparison on x.y.z only)."""
    a = _semver_tuple(current)
    b = _semver_tuple(latest)
    if a is None or b is None:
        return False
    return a < b


def _resolve_install_root(identity: DesktopComponentIdentity) -> Path:
    if is_frozen():
        base = runtime_base_dir()
        if base.name.lower() == "current":
            return base.parent
        return base.parent

    env_specific = os.environ.get(f"MONCLUB_{identity.component_id.upper()}_INSTALL_ROOT")
    env_generic = os.environ.get("MONCLUB_INSTALL_ROOT")
    for raw in (env_specific, env_generic):
        if not raw:
            continue
        candidate = Path(raw).expanduser()
        if candidate.exists():
            return candidate

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        for root_name in (identity.default_install_root_name, *identity.legacy_install_root_names):
            candidate = Path(local_app_data) / root_name
            if candidate.exists():
                return candidate

    program_data = os.environ.get("PROGRAMDATA") or os.environ.get("ProgramData")
    if program_data:
        for root_name in identity.legacy_install_root_names:
            candidate = Path(program_data) / root_name
            if candidate.exists():
                return candidate

    return get_desktop_path_layout().data_root


def _download_dir(install_root: Path, platform: str, channel: str) -> Path:
    return install_root / "downloads" / _lower(platform) / _lower(channel)


def _updater_exe_path(install_root: Path, identity: DesktopComponentIdentity) -> Path:
    return install_root / "updater" / identity.updater_exe_name


def _launch_as_admin(exe_path: Path) -> None:
    """Launch an executable as administrator on Windows."""
    if os.name == "nt":
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", str(exe_path), None, str(exe_path.parent), 1
        )
    else:
        subprocess.Popen([str(exe_path)], cwd=str(exe_path.parent))


@dataclass
class UpdateStatus:
    # Current installed version info
    current_version: str = "0.0.0"
    current_codename: str = ""

    # Latest available version info
    latest_version: Optional[str] = None
    latest_codename: Optional[str] = None
    release_date: Optional[str] = None
    available_until: Optional[str] = None
    size_bytes: Optional[int] = None
    release_notes: Optional[str] = None
    download_url: Optional[str] = None
    min_compatible_version: Optional[str] = None

    # Download state
    update_available: bool = False
    downloaded: bool = False
    download_path: Optional[str] = None
    downloading: bool = False
    progress_percent: Optional[int] = None

    # Meta
    last_check_at: float = 0.0
    last_error: Optional[str] = None

    # Legacy fields (backward compat with old code that reads these)
    current_release_id: str = "dev"
    latest_release: Optional[Dict[str, Any]] = None
    download_progress: Optional[int] = None
    progress: Optional[int] = None


class ComponentUpdateManager:
    """Component-aware updater engine with independent runtime state."""

    def __init__(
        self,
        *,
        component: DesktopComponentIdentity,
        app,
        cfg,
        logger,
        api_factory: Callable[[], Any],
    ) -> None:
        self.component = component
        self.app = app
        self.cfg = cfg
        self.logger = logger
        self._api_factory = api_factory

        self._lock = threading.RLock()
        self._running = False
        self._after_id: Optional[str] = None
        self._worker_running = False
        self._token: Optional[str] = None
        self._force_download_once = False
        self._session = requests.Session()
        self.install_root = _resolve_install_root(component)
        self.status = UpdateStatus(
            current_version=self.get_current_version(),
            current_codename=self.get_current_codename(),
            current_release_id=self.get_current_release_id(),
        )
        self._notified_version: Optional[str] = None
        self._last_progress_emit_at: float = 0.0
        self._last_progress_emit_pct: Optional[int] = None

    def get_current_version(self) -> str:
        """Read the installed version from version.json (x.y.z format)."""
        try:
            base = runtime_base_dir()
            data = _parse_json_file(base / "version.json")
            v = _safe_str(data.get("version") or data.get("releaseId") or "", "")
            # If it's a releaseId (timestamp), return "0.0.0" so any real version triggers update
            if v and _semver_tuple(v):
                return v
            return "0.0.0"
        except Exception:
            return "0.0.0"

    def get_current_codename(self) -> str:
        try:
            base = runtime_base_dir()
            data = _parse_json_file(base / "version.json")
            return _safe_str(data.get("codename"), "")
        except Exception:
            return ""

    def get_current_release_id(self) -> str:
        """Legacy: return releaseId for backward compat."""
        try:
            base = runtime_base_dir()
            data = _parse_json_file(base / "version.json")
            rid = _safe_str(
                data.get("releaseId") or data.get("release_id") or data.get("version") or "",
                "",
            )
            return rid or "dev"
        except Exception:
            return "dev"

    def _platform(self) -> str:
        return _safe_str(getattr(self.cfg, "update_platform", "WINDOWS"), "WINDOWS").upper()

    def _channel(self) -> str:
        return _safe_str(getattr(self.cfg, "update_channel", "stable"), "stable").lower()

    def _interval_ms(self) -> int:
        sec = int(getattr(self.cfg, "update_check_interval_sec", 3 * 60 * 60) or (3 * 60 * 60))
        if sec < 60:
            sec = 60
        return sec * 1000

    def _auto_download(self) -> bool:
        return bool(getattr(self.cfg, "update_auto_download_zip", False))

    def start(self, *, token: str, check_now: bool = True) -> None:
        token = _safe_str(token, "")
        if not token or not bool(getattr(self.cfg, "update_enabled", True)):
            return

        with self._lock:
            self._token = token
            if not self._running:
                self._running = True
                self.status.current_version = self.get_current_version()
                self.status.current_codename = self.get_current_codename()
                self.status.current_release_id = self.get_current_release_id()
                self.logger.info(
                    "[Update:%s] started (platform=%s channel=%s version=%s installRoot=%s)",
                    self.component.component_id,
                    self._platform(),
                    self._channel(),
                    self.status.current_version,
                    str(self.install_root),
                )
            if check_now:
                self._schedule_next(0)
            elif self._after_id is None:
                self._schedule_next(self._interval_ms())

    def stop(self) -> None:
        with self._lock:
            self._running = False
            self._token = None
            self._force_download_once = False
            if self._after_id is not None:
                try:
                    self.app.after_cancel(self._after_id)
                except Exception:
                    pass
                self._after_id = None

    def request_check_now(self) -> None:
        with self._lock:
            if not self._running:
                return
        self._schedule_next(0)

    def request_download(self) -> None:
        with self._lock:
            if not self._running or not self._token:
                return
            self._force_download_once = True
        self._schedule_next(0)

    def cancel_download(self) -> None:
        """Delete any downloaded installer file and reset download state."""
        with self._lock:
            path = self.status.download_path
            self.status.downloaded = False
            self.status.download_path = None
            self.status.downloading = False
            self.status.progress_percent = None
            self.status.progress = None
            self.status.download_progress = None

        if path:
            try:
                p = Path(path)
                if p.exists():
                    p.unlink(missing_ok=True)
                    self.logger.info("[Update:%s] cancelled download, deleted: %s", self.component.component_id, path)
            except Exception as exc:
                self.logger.warning("[Update:%s] cancel_download delete failed: %s", self.component.component_id, exc)

        try:
            self.app.after(0, lambda: self.app.on_update_status_changed(self.status))
        except Exception:
            pass

    def _schedule_next(self, delay_ms: int) -> None:
        with self._lock:
            if not self._running:
                return
            if self._after_id is not None:
                try:
                    self.app.after_cancel(self._after_id)
                except Exception:
                    pass
                self._after_id = None
            self._after_id = self.app.after(delay_ms, self._tick)

    def _consume_force_download(self) -> bool:
        with self._lock:
            value = bool(self._force_download_once)
            self._force_download_once = False
            return value

    def _tick(self) -> None:
        self._schedule_next(self._interval_ms())
        with self._lock:
            if not self._running or self._worker_running:
                return
            token = _safe_str(self._token, "")
            if not token:
                return
            self._worker_running = True
            force_download = self._consume_force_download()

        def work() -> None:
            try:
                self._run_check_and_download(token=token, force_download=force_download)
            finally:
                with self._lock:
                    self._worker_running = False

        threading.Thread(
            target=work,
            daemon=True,
            name=f"{self.component.component_id}-update-check",
        ).start()

    def _run_check_and_download(self, *, token: str, force_download: bool = False) -> None:
        try:
            current_version = self.get_current_version()
            current_release_id = self.get_current_release_id()
            self.status.current_version = current_version
            self.status.current_codename = self.get_current_codename()
            self.status.current_release_id = current_release_id

            api = self._api_factory()
            latest = api.get_latest_software_release(
                token=token,
                platform=self._platform(),
                channel=self._channel(),
                current_version=current_version,
                target=self.component.component_id,
                release_id=current_release_id if current_release_id != "dev" else None,
                timeout=20,
            )

            self.status.last_check_at = time.time()
            self.status.last_error = None

            # Check if update is available (backend sets shouldUpdate)
            should_update = bool(latest.get("shouldUpdate", False))

            # Also do local semver comparison as fallback
            latest_version = _safe_str(latest.get("version"), "")
            if not should_update and latest_version:
                should_update = _is_version_outdated(current_version, latest_version)

            if not should_update or not latest_version:
                self._set_update_available(False, downloaded=False, latest=latest)
                return

            # Map new response format
            self.status.latest_version = latest_version
            self.status.latest_codename = _safe_str(latest.get("codename"), "")
            self.status.release_date = _safe_str(latest.get("publishedAt") or latest.get("releaseDate"), "")
            self.status.available_until = _safe_str(latest.get("availableUntil"), "")
            self.status.release_notes = _safe_str(latest.get("releaseNotes") or latest.get("notes"), "")
            self.status.min_compatible_version = _safe_str(latest.get("minCompatibleVersion") or latest.get("lastCompatibleReleaseId"), "")

            # Determine download URL (prefer installer, fall back to zip)
            installer_obj = latest.get("installer") or {}
            zip_obj = latest.get("zip") or {}
            installer_url = _safe_str(installer_obj.get("url"), "")
            installer_name = _safe_str(installer_obj.get("name"), "")
            installer_size = installer_obj.get("size")
            zip_url = _safe_str(zip_obj.get("url"), "")
            zip_name = _safe_str(zip_obj.get("name"), "")

            self.status.size_bytes = installer_size or latest.get("sizeBytes")

            # Use installer URL if available, otherwise fall back to zip
            if installer_url:
                download_url = installer_url
                download_name = installer_name or f"{self.component.artifact_name}-{latest_version}-installer.exe"
            elif zip_url:
                download_url = zip_url
                download_name = zip_name or f"{self.component.artifact_name}-{latest_version}.zip"
            else:
                self._set_update_available(True, downloaded=False, latest=latest)
                return

            self.status.download_url = download_url
            self.status.latest_release = latest

            ddir = _download_dir(self.install_root, self._platform(), self._channel())
            ddir.mkdir(parents=True, exist_ok=True)
            download_path = ddir / download_name

            # Check if already downloaded
            if download_path.exists() and download_path.stat().st_size > 0:
                self._set_update_available(True, downloaded=True, latest=latest, download_path=download_path)
                return

            if not self._auto_download() and not force_download:
                self._set_update_available(True, downloaded=False, latest=latest)
                return

            # Download the file
            self._download_to_file(download_url, download_path, timeout=300, label="installer")

            self._set_update_available(True, downloaded=True, latest=latest, download_path=download_path)

        except Exception as exc:
            msg = str(exc)
            self.status.last_error = msg
            self.logger.warning("[Update:%s] failed: %s", self.component.component_id, msg)
            try:
                self.app.after(0, lambda: self.app.on_update_error(msg))
            except Exception:
                pass
        finally:
            self._set_downloading(False, None)

    def _set_downloading(self, downloading: bool, progress: Optional[int]) -> None:
        try:
            self.status.downloading = bool(downloading)
            self.status.progress = progress
            self.status.download_progress = progress
            self.status.progress_percent = progress
        except Exception:
            pass

        try:
            now = time.time()
            pct = progress
            if not downloading:
                self._last_progress_emit_at = now
                self._last_progress_emit_pct = pct
                self.app.after(0, lambda: self.app.on_update_status_changed(self.status))
                return
            if pct is not None:
                if self._last_progress_emit_pct == pct and (now - self._last_progress_emit_at) < 0.25:
                    return
                if (now - self._last_progress_emit_at) < 0.25:
                    return
            self._last_progress_emit_at = now
            self._last_progress_emit_pct = pct
            self.app.after(0, lambda: self.app.on_update_status_changed(self.status))
        except Exception:
            pass

    def _download_to_file(self, url: str, path: Path, *, timeout: int, label: str = "") -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".part")
        self.logger.info("[Update:%s] downloading (%s) -> %s", self.component.component_id, label or "file", url)
        self._set_downloading(True, 0)
        r = self._session.get(url, stream=True, timeout=timeout)
        if r.status_code < 200 or r.status_code >= 300:
            self._set_downloading(False, None)
            raise RuntimeError(f"Download failed: HTTP {r.status_code} -> {url}")

        total = 0
        try:
            total = int(r.headers.get("Content-Length") or "0")
        except Exception:
            total = 0

        done = 0
        last_pct: Optional[int] = None
        with tmp.open("wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 256):
                if not chunk:
                    continue
                f.write(chunk)
                done += len(chunk)
                if total > 0:
                    pct = int((done * 100) / total)
                    pct = max(0, min(100, pct))
                    if last_pct != pct:
                        last_pct = pct
                        self._set_downloading(True, pct)
        tmp.replace(path)
        self._set_downloading(False, None)

    def _set_update_available(
        self,
        available: bool,
        *,
        downloaded: bool,
        latest: Optional[Dict[str, Any]],
        download_path: Optional[Path] = None,
    ) -> None:
        self.status.update_available = available
        self.status.downloaded = downloaded
        self.status.latest_release = latest
        self.status.download_path = str(download_path) if download_path else None
        if downloaded:
            self.status.downloading = False
            self.status.progress = None
            self.status.download_progress = None
            self.status.progress_percent = None
        try:
            self.app.after(0, lambda: self.app.on_update_status_changed(self.status))
        except Exception:
            pass

        if available and downloaded and latest:
            ver = _safe_str(latest.get("version"), "")
            if ver and ver != self._notified_version:
                self._notified_version = ver
                try:
                    self.app.after(0, lambda: self.app.on_update_ready(self.status))
                except Exception:
                    pass

    def can_install_now(self) -> Tuple[bool, str]:
        if not self.status.update_available:
            return False, "No update available."
        if not self.status.downloaded:
            return False, "Update not downloaded yet."
        if not self.status.download_path:
            return False, "Download path is missing."
        p = Path(self.status.download_path)
        if not p.exists():
            return False, "Downloaded file is missing."
        return True, "OK"

    def launch_updater_and_exit(self) -> None:
        ok, reason = self.can_install_now()
        if not ok:
            raise RuntimeError(reason)

        download_path = Path(self.status.download_path or "")
        ext = download_path.suffix.lower()

        self.logger.info("[Update:%s] launching installer: %s", self.component.component_id, str(download_path))

        if ext == ".exe":
            # Launch installer as admin
            _launch_as_admin(download_path)
        else:
            # Legacy: fall back to the C# updater for ZIP files
            updater = _updater_exe_path(self.install_root, self.component)
            if not updater.exists():
                raise RuntimeError(f"Updater not found: {updater}")

            latest = self.status.latest_release or {}
            rid = _safe_str(latest.get("releaseId") or latest.get("version"), "")
            args = [
                str(updater),
                "--installRoot", str(self.install_root),
                "--releaseId", rid,
                "--zip", str(download_path),
                "--waitPid", str(os.getpid()),
                "--appExeName", self.component.main_exe_name,
            ]
            try:
                log_dir = self.install_root / "logs"
                log_dir.mkdir(parents=True, exist_ok=True)
                log_path = log_dir / f"{self.component.component_id}-updater-{rid}.log"
                args += ["--log", str(log_path)]
            except Exception:
                pass

            self.logger.info("[Update:%s] spawning C# updater: %s", self.component.component_id, " ".join(args))
            subprocess.Popen(
                args,
                cwd=str(self.install_root),
                close_fds=True,
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
                ) if os.name == "nt" else 0,
            )


__all__ = ["ComponentUpdateManager", "UpdateStatus"]

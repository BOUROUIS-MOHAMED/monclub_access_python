"""Shared component-aware update runtime used by Access and TV."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

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


def _parse_version_json(p: Path) -> Dict[str, Any]:
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


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


@dataclass
class UpdateStatus:
    current_release_id: str
    latest_release: Optional[Dict[str, Any]] = None
    update_available: bool = False
    downloaded: bool = False
    download_path: Optional[str] = None
    manifest_path: Optional[str] = None
    last_check_at: float = 0.0
    last_error: Optional[str] = None
    downloading: bool = False
    progress: Optional[int] = None
    download_progress: Optional[int] = None
    progress_percent: Optional[int] = None


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
        self.status = UpdateStatus(current_release_id=self.get_current_release_id())
        self._notified_release_id: Optional[str] = None
        self._last_progress_emit_at: float = 0.0
        self._last_progress_emit_pct: Optional[int] = None

    def get_current_release_id(self) -> str:
        try:
            base = runtime_base_dir()
            version_json = base / "version.json"
            data = _parse_version_json(version_json)
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
        return bool(getattr(self.cfg, "update_auto_download_zip", True))

    def start(self, *, token: str, check_now: bool = True) -> None:
        token = _safe_str(token, "")
        if not token or not bool(getattr(self.cfg, "update_enabled", True)):
            return

        with self._lock:
            self._token = token
            if not self._running:
                self._running = True
                self.status.current_release_id = self.get_current_release_id()
                self.logger.info(
                    "[Update:%s] started (platform=%s channel=%s currentReleaseId=%s installRoot=%s)",
                    self.component.component_id,
                    self._platform(),
                    self._channel(),
                    self.status.current_release_id,
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
            current = self.get_current_release_id()
            self.status.current_release_id = current
            api = self._api_factory()
            latest = api.get_latest_software_release(
                token=token,
                platform=self._platform(),
                channel=self._channel(),
                release_id=current if current else None,
                timeout=20,
            )

            self.status.last_check_at = time.time()
            self.status.last_error = None
            self.status.latest_release = latest

            latest_id = _safe_str(latest.get("releaseId"), "")
            if not latest_id or latest_id == current:
                self._set_update_available(False, downloaded=False, latest=None)
                return

            ddir = _download_dir(self.install_root, self._platform(), self._channel())
            ddir.mkdir(parents=True, exist_ok=True)

            zip_obj = latest.get("zip") or {}
            man_obj = latest.get("manifest") or {}
            zip_name = _safe_str(zip_obj.get("name"), f"{self.component.artifact_name}-{latest_id}.zip")
            man_name = _safe_str(
                man_obj.get("name"),
                f"{self.component.artifact_name}-{latest_id}.manifest.json",
            )
            zip_url = _safe_str(zip_obj.get("url"), "")
            man_url = _safe_str(man_obj.get("url"), "")
            zip_path = ddir / zip_name
            man_path = ddir / man_name

            ok_cached = False
            if zip_path.exists() and man_path.exists():
                ok_cached = self._verify_cached(zip_path=zip_path, manifest_path=man_path)
            if ok_cached:
                self._set_update_available(
                    True,
                    downloaded=True,
                    latest=latest,
                    zip_path=zip_path,
                    manifest_path=man_path,
                )
                return

            if (not self._auto_download()) and (not force_download):
                self._set_update_available(True, downloaded=False, latest=latest)
                return

            if not man_url:
                raise RuntimeError("latest.manifest.url is empty.")
            self._download_to_file(man_url, man_path, timeout=30, label="manifest")
            expected_zip_sha = self._extract_zip_sha_from_manifest(man_path)
            if not expected_zip_sha:
                raise RuntimeError("manifest.outputs.zipSha256 missing/invalid.")

            if not zip_url:
                raise RuntimeError("latest.zip.url is empty.")
            self._download_to_file(zip_url, zip_path, timeout=180, label="zip")

            got_sha = _sha256_file(zip_path)
            if got_sha != expected_zip_sha:
                try:
                    zip_path.unlink(missing_ok=True)
                except Exception:
                    pass
                raise RuntimeError(f"ZIP sha256 mismatch: expected={expected_zip_sha} got={got_sha}")

            self._set_update_available(
                True,
                downloaded=True,
                latest=latest,
                zip_path=zip_path,
                manifest_path=man_path,
            )
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

    def _extract_zip_sha_from_manifest(self, manifest_path: Path) -> str:
        if not manifest_path.is_file():
            return ""
        try:
            content = manifest_path.read_text(encoding="utf-8-sig")
            data = json.loads(content)
        except Exception:
            return ""

        for path in (
            ("outputs", "zipSha256"),
            ("zipSha256",),
            ("sha256",),
            ("checksum",),
            ("hash",),
            ("sha",),
        ):
            value = data
            try:
                for key in path:
                    value = value[key]
                sha = _safe_str(value, "").lower()
                if sha:
                    return sha
            except Exception:
                continue
        return ""

    def _verify_cached(self, *, zip_path: Path, manifest_path: Path) -> bool:
        try:
            expected = self._extract_zip_sha_from_manifest(manifest_path)
            if not expected:
                return False
            got = _sha256_file(zip_path)
            return got == expected
        except Exception:
            return False

    def _set_update_available(
        self,
        available: bool,
        *,
        downloaded: bool,
        latest: Optional[Dict[str, Any]],
        zip_path: Optional[Path] = None,
        manifest_path: Optional[Path] = None,
    ) -> None:
        self.status.update_available = available
        self.status.downloaded = downloaded
        self.status.latest_release = latest
        self.status.download_path = str(zip_path) if zip_path else None
        self.status.manifest_path = str(manifest_path) if manifest_path else None
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
            rid = _safe_str(latest.get("releaseId"), "")
            if rid and rid != self._notified_release_id:
                self._notified_release_id = rid
                try:
                    self.app.after(0, lambda: self.app.on_update_ready(self.status))
                except Exception:
                    pass

    def can_install_now(self) -> Tuple[bool, str]:
        if not self.status.update_available:
            return False, "No update available."
        if not self.status.downloaded:
            return False, "Update not downloaded yet."
        if not self.status.download_path or not Path(self.status.download_path).exists():
            return False, "Downloaded ZIP is missing."
        if not self.status.manifest_path or not Path(self.status.manifest_path).exists():
            return False, "Downloaded manifest is missing."

        updater = _updater_exe_path(self.install_root, self.component)
        if not updater.exists():
            self.logger.error("[Update:%s] Updater missing at: %s", self.component.component_id, updater)
            return False, f"Updater not installed yet: {updater}"
        return True, "OK"

    def launch_updater_and_exit(self) -> None:
        ok, reason = self.can_install_now()
        if not ok:
            raise RuntimeError(reason)

        updater = _updater_exe_path(self.install_root, self.component)
        zip_path = Path(self.status.download_path or "")
        man_path = Path(self.status.manifest_path or "")
        rid = _safe_str((self.status.latest_release or {}).get("releaseId"), "")

        args = [
            str(updater),
            "--installRoot", str(self.install_root),
            "--releaseId", rid,
            "--zip", str(zip_path),
            "--manifest", str(man_path),
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

        try:
            fk = int(getattr(self.cfg, "update_force_kill_after_seconds", 20))
            if fk > 0:
                args += ["--forceKillAfterSeconds", str(fk)]
        except Exception:
            pass

        self.logger.info("[Update:%s] spawning updater: %s", self.component.component_id, " ".join(args))
        subprocess.Popen(
            args,
            cwd=str(self.install_root),
            close_fds=True,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            ) if os.name == "nt" else 0,
        )


__all__ = ["ComponentUpdateManager", "UpdateStatus"]

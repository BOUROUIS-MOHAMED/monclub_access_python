# monclub_access_python/app/core/update_manager.py
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

from app.core.utils import is_frozen, runtime_base_dir, DATA_ROOT


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    try:
        s = str(v).strip()
        return s if s else default
    except Exception:
        return default


def _lower(s: Any) -> str:
    return _safe_str(s, "").lower()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _parse_version_json(p: Path) -> Dict[str, Any]:
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _resolve_install_root() -> Path:
    """
    In frozen onedir install layout:
      %LOCALAPPDATA%\\MonClubAccess\\current\\MonClubAccess.exe
      install_root == ...\\MonClubAccess

    In dev:
      - If an existing installation is found (e.g., from a previous frozen install),
        use that as install_root (so updater can be launched).
      - Otherwise fallback to DATA_ROOT.
    """
    if is_frozen():
        base = runtime_base_dir()
        # common: <install_root>/current
        if base.name.lower() == "current":
            return base.parent
        # fallback: treat exe dir parent as root
        return base.parent

    # --- Development mode: try to detect an existing installation ---
    # 1. Per‑user install (most common for frozen builds)
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidate = Path(local_app_data) / "MonClubAccess"
        if candidate.exists():
            return candidate

    # 2. Machine‑wide install (if configured)
    prog_data = os.environ.get("ProgramData")
    if prog_data:
        candidate = Path(prog_data) / "MonClub Access"
        if candidate.exists():
            return candidate

    # 3. Environment override (for testing)
    override = os.environ.get("MONCLUB_INSTALL_ROOT")
    if override:
        candidate = Path(override)
        if candidate.exists():
            return candidate

    # 4. Fallback to DATA_ROOT (your dev data directory)
    return DATA_ROOT

def _download_dir(install_root: Path, platform: str, channel: str) -> Path:
    # keep consistent + predictable
    return install_root / "downloads" / _lower(platform) / _lower(channel)


def _updater_exe_path(install_root: Path) -> Path:
    return install_root / "updater" / "MonClubAccessUpdater.exe"


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

    # UI-friendly download state (your app.py reads these with getattr)
    downloading: bool = False
    progress: Optional[int] = None
    download_progress: Optional[int] = None
    progress_percent: Optional[int] = None


class UpdateManager:
    """
    - Decides + downloads in MonClub Access (this class)
    - Installer/updater (later) only installs when user confirms
    """

    def __init__(self, *, app, cfg, logger, api_factory):
        """
        app: Tk root (MainApp)
        cfg: AppConfig
        logger: logger
        api_factory: callable returning MonClubApi (your self._api)
        """
        self.app = app
        self.cfg = cfg
        self.logger = logger
        self._api_factory = api_factory

        self._lock = threading.RLock()
        self._running = False
        self._after_id: Optional[str] = None
        self._worker_running = False

        # token is stored here (so scheduled ticks don't capture stale tokens)
        self._token: Optional[str] = None

        # manual download trigger (one-shot)
        self._force_download_once = False

        self._session = requests.Session()

        self.install_root = _resolve_install_root()

        # state exposed to UI
        self.status = UpdateStatus(current_release_id=self.get_current_release_id())

        # dedupe: show "update ready" notification once per releaseId
        self._notified_release_id: Optional[str] = None

        # throttle UI progress updates
        self._last_progress_emit_at: float = 0.0
        self._last_progress_emit_pct: Optional[int] = None

    # ------------------------
    # Version / identity
    # ------------------------
    def get_current_release_id(self) -> str:
        """
        Read from version.json shipped inside current folder (or runtime folder in frozen).
        If missing, fallback to "dev".
        """
        try:
            base = runtime_base_dir()
            p = base / "version.json"
            j = _parse_version_json(p)
            rid = _safe_str(j.get("releaseId") or j.get("release_id") or j.get("version") or "", "")
            return rid or "dev"
        except Exception:
            return "dev"

    def _platform(self) -> str:
        v = _safe_str(getattr(self.cfg, "update_platform", "WINDOWS"), "WINDOWS")
        return v.upper()

    def _channel(self) -> str:
        v = _safe_str(getattr(self.cfg, "update_channel", "stable"), "stable")
        return v.lower()

    def _interval_ms(self) -> int:
        sec = int(getattr(self.cfg, "update_check_interval_sec", 3 * 60 * 60) or (3 * 60 * 60))
        if sec < 60:
            sec = 60
        return sec * 1000

    def _auto_download(self) -> bool:
        return bool(getattr(self.cfg, "update_auto_download_zip", True))

    # ------------------------
    # Public controls
    # ------------------------
    def start(self, *, token: str, check_now: bool = True) -> None:
        """
        Starts the periodic checker (and optionally runs an immediate check).

        check_now=True  -> immediate check (startup behavior)
        check_now=False -> just ensure running + token is set, next tick will occur on schedule
        """
        token = _safe_str(token, "")
        if not token:
            return

        with self._lock:
            self._token = token

            if not self._running:
                self._running = True
                self.status.current_release_id = self.get_current_release_id()
                self.logger.info(
                    "[Update] started (platform=%s channel=%s currentReleaseId=%s installRoot=%s)",
                    self._platform(),
                    self._channel(),
                    self.status.current_release_id,
                    str(self.install_root),
                )

            # startup: run immediately
            if check_now:
                self._schedule_next(0)
            else:
                # ensure at least scheduled (if not already)
                if self._after_id is None:
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
        """Best-effort immediate check (uses stored token)."""
        with self._lock:
            if not self._running:
                return
        self._schedule_next(0)

    def request_download(self) -> None:
        """
        Manual download trigger (no args) so MainApp can call it via reflection.
        This forces download even if cfg.update_auto_download_zip is False.
        """
        with self._lock:
            if not self._running:
                return
            if not self._token:
                return
            self._force_download_once = True
        self._schedule_next(0)

    # ------------------------
    # Scheduler internals
    # ------------------------
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
            v = bool(self._force_download_once)
            self._force_download_once = False
            return v

    def _tick(self) -> None:
        # schedule next first (even if this run fails)
        self._schedule_next(self._interval_ms())

        with self._lock:
            if not self._running:
                return
            if self._worker_running:
                self.logger.debug("[Update] tick skipped: worker already running")
                return
            token = _safe_str(self._token, "")
            if not token:
                self.logger.debug("[Update] tick skipped: no token")
                return

            self._worker_running = True
            force_download = self._consume_force_download()

        def work():
            try:
                self._run_check_and_download(token=token, force_download=force_download)
            finally:
                with self._lock:
                    self._worker_running = False

        threading.Thread(target=work, daemon=True).start()

    # ------------------------
    # Core logic
    # ------------------------
    def _run_check_and_download(self, *, token: str, force_download: bool = False) -> None:
        try:
            current = self.get_current_release_id()
            self.status.current_release_id = current

            api = self._api_factory()

            latest = api.get_latest_access_software_release(
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
                # no update
                if self.status.update_available:
                    self.logger.info("[Update] update cleared (now latest == current)")
                self._set_update_available(False, downloaded=False, latest=None)
                return

            # update available
            self.logger.info("[Update] update available: %s -> %s", current, latest_id)

            # ensure download dir
            ddir = _download_dir(self.install_root, self._platform(), self._channel())
            ddir.mkdir(parents=True, exist_ok=True)

            zip_obj = latest.get("zip") or {}
            man_obj = latest.get("manifest") or {}

            zip_name = _safe_str(zip_obj.get("name"), f"MonClubAccess-{latest_id}.zip")
            man_name = _safe_str(man_obj.get("name"), f"MonClubAccess-{latest_id}.manifest.json")

            zip_url = _safe_str(zip_obj.get("url"), "")
            man_url = _safe_str(man_obj.get("url"), "")

            zip_path = ddir / zip_name
            man_path = ddir / man_name

            # check if already downloaded and verified
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

            # if auto-download disabled and not forced: only mark available
            if (not self._auto_download()) and (not force_download):
                self._set_update_available(True, downloaded=False, latest=latest, zip_path=None, manifest_path=None)
                return

            # download manifest first (needed for sha)
            if not man_url:
                raise RuntimeError("latest.manifest.url is empty (backend release response).")
            self._download_to_file(man_url, man_path, timeout=30, label="manifest")

            # verify + get zip sha from manifest
            expected_zip_sha = self._extract_zip_sha_from_manifest(man_path)
            if not expected_zip_sha:
                raise RuntimeError("manifest.outputs.zipSha256 missing/invalid.")

            if not zip_url:
                raise RuntimeError("latest.zip.url is empty (backend release response).")
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

        except Exception as e:
            msg = str(e)
            self.status.last_error = msg
            self.logger.warning("[Update] failed: %s", msg)
            try:
                self.app.after(0, lambda: self.app.on_update_error(msg))  # type: ignore[attr-defined]
            except Exception:
                pass
        finally:
            # ensure download flags cleared
            self._set_downloading(False, None)

    def _set_downloading(self, downloading: bool, progress: Optional[int]) -> None:
        """
        Thread-safe-ish state update (we still push UI updates via after()).
        """
        try:
            self.status.downloading = bool(downloading)
            self.status.progress = progress
            self.status.download_progress = progress
            self.status.progress_percent = progress
        except Exception:
            pass

        # notify UI (throttled for progress updates)
        try:
            now = time.time()
            pct = progress

            if not downloading:
                # always emit when ending
                self._last_progress_emit_at = now
                self._last_progress_emit_pct = pct
                self.app.after(0, lambda: self.app.on_update_status_changed(self.status))  # type: ignore[attr-defined]
                return

            # downloading: throttle
            if pct is not None:
                if self._last_progress_emit_pct == pct and (now - self._last_progress_emit_at) < 0.25:
                    return
                if (now - self._last_progress_emit_at) < 0.25:
                    return

            self._last_progress_emit_at = now
            self._last_progress_emit_pct = pct
            self.app.after(0, lambda: self.app.on_update_status_changed(self.status))  # type: ignore[attr-defined]
        except Exception:
            pass

    def _download_to_file(self, url: str, path: Path, *, timeout: int, label: str = "") -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".part")

        self.logger.info("[Update] downloading (%s) -> %s", label or "file", url)

        # start download UI state
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
                    if pct < 0:
                        pct = 0
                    if pct > 100:
                        pct = 100
                    if last_pct != pct:
                        last_pct = pct
                        self._set_downloading(True, pct)

        tmp.replace(path)

        # end download UI state (keep it until next state sets downloaded)
        self._set_downloading(False, None)

    def _extract_zip_sha_from_manifest(self, manifest_path: Path) -> str:
        """
        Extract the ZIP SHA256 from the manifest JSON.
        Tries multiple possible key paths and logs detailed errors.
        """
        # 1. Ensure the file exists
        if not manifest_path.is_file():
            self.logger.error("[Update] Manifest file does not exist: %s", manifest_path)
            return ""

        # 2. Read and parse JSON with explicit error logging
        try:
            content = manifest_path.read_text(encoding="utf-8-sig")  # handles BOM
            j = json.loads(content)
        except Exception as e:
            self.logger.error("[Update] Failed to read/parse manifest: %s", e, exc_info=True)
            return ""

        # 3. Define possible paths to the SHA256 value
        possible_paths = [
            ["outputs", "zipSha256"],
            ["zipSha256"],
            ["sha256"],
            ["checksum"],
            ["hash"],
            ["sha"],
        ]

        for path in possible_paths:
            value = j
            try:
                for key in path:
                    value = value[key]
                sha = _safe_str(value, "").lower()
                if sha:
                    self.logger.debug("[Update] Found SHA256 at manifest path: %s", ".".join(path))
                    return sha
            except (KeyError, TypeError, IndexError):
                continue

        # 4. No SHA found – log available keys for debugging
        self.logger.warning(
            "[Update] No SHA256 found in manifest. Top-level keys: %s",
            list(j.keys())
        )
        # Optionally log full manifest at DEBUG level for deeper inspection
        self.logger.debug("[Update] Manifest content:\n%s", json.dumps(j, indent=2))
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

    # ------------------------
    # UI integration
    # ------------------------
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

        # downloading/progress should be cleared when update state is finalized
        if downloaded:
            self.status.downloading = False
            self.status.progress = None
            self.status.download_progress = None
            self.status.progress_percent = None

        # notify UI (must be on main thread)
        try:
            self.app.after(0, lambda: self.app.on_update_status_changed(self.status))  # type: ignore[attr-defined]
        except Exception:
            pass

        # show a one-time “ready” notification
        if available and downloaded and latest:
            rid = _safe_str(latest.get("releaseId"), "")
            if rid and rid != self._notified_release_id:
                self._notified_release_id = rid
                try:
                    self.app.after(0, lambda: self.app.on_update_ready(self.status))  # type: ignore[attr-defined]
                except Exception:
                    pass

    # ------------------------
    # Launch updater (later)
    # ------------------------
    def can_install_now(self) -> Tuple[bool, str]:
        if not self.status.update_available:
            return False, "No update available."
        if not self.status.downloaded:
            return False, "Update not downloaded yet."
        if not self.status.download_path or not Path(self.status.download_path).exists():
            return False, "Downloaded ZIP is missing."
        if not self.status.manifest_path or not Path(self.status.manifest_path).exists():
            return False, "Downloaded manifest is missing."

        upd = _updater_exe_path(self.install_root)
        if not upd.exists():
            self.logger.error("[Update] Updater missing at: %s", upd)
            return False, f"Updater not installed yet: {upd}"
        return True, "OK"

    def launch_updater_and_exit(self) -> None:
        ok, reason = self.can_install_now()
        if not ok:
            raise RuntimeError(reason)

        upd = _updater_exe_path(self.install_root)
        zip_path = Path(self.status.download_path or "")
        man_path = Path(self.status.manifest_path or "")
        rid = _safe_str((self.status.latest_release or {}).get("releaseId"), "")

        args = [
            str(upd),
            "--installRoot", str(self.install_root),
            "--releaseId", rid,
            "--zip", str(zip_path),
            "--manifest", str(man_path),
            "--waitPid", str(os.getpid()),
        ]

        # Optional: write updater logs under installRoot/logs (same folder the installer pre-creates)
        try:
            log_dir = self.install_root / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = log_dir / f"updater-{rid}.log"
            args += ["--log", str(log_path)]
        except Exception:
            # Logging is optional; ignore errors constructing the log path
            pass

        # Optional: force-kill timeout (helps if MonClubAccess is stuck)
        try:
            fk = int(getattr(self.cfg, "update_force_kill_after_seconds", 20))
            if fk > 0:
                args += ["--forceKillAfterSeconds", str(fk)]
        except Exception:
            pass

        self.logger.info("[Update] spawning updater: %s", " ".join(args))

        subprocess.Popen(
            args,
            cwd=str(self.install_root),
            close_fds=True,
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS) if os.name == "nt" else 0,
        )

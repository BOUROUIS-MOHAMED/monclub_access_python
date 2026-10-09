"""Shared update engine used by Access and TV (updater v2, docs/access-updater-v2/design.md section 7).

One engine, two targets (``access`` / ``tv``). What it does:

- **Check** at start-up and every interval (3 h default), retrying a failed check after
  60 s / 5 min / 15 min. Sends ``capabilities=signed-v1``. 404 / ``shouldUpdate=false`` is
  "no update" (D16) and discards any pending download (Pause / Withdraw reach the PC so).
- **Accept** only a signed offer (shared/release_manifest.py). Otherwise VERIFY_FAILED,
  reported once per version, nothing downloaded (D3).
- **Download** to ``downloads\\<target>\\<channel>\\<version>\\<installerName>.part``, check size
  and SHA-256, then rename. A cached file is reused only when its SHA-256 matches (D11, D12).
  Cancel aborts a running download (D37). Other versions' folders are deleted (D35).
- **Install** (button, start-up, or the 24 h fallback): re-check SHA-256, start the hidden
  wrapper (shared/update_wrapper.py), and only when it is alive tell the caller to quit (D1).
- **Start-up** (``startup_gate``), before any door work: consume the installer's result,
  then install a verified pending update after a 5 s server re-check (O1, D25).
- **Loop guard** in ``{app}\\state\\update_state.json``: a crash / failed-after-copy result bans
  the version from auto-install; a health timeout (or no result at all) gets one retry.
- **Health marker** ``boot_ok.json`` once the local API listens (``on_local_api_ready``).
- **Telemetry** (D19): every result goes to an outbox in update_state.json and is POSTed to
  ``softwareUpdateEvent`` with an idempotent ``eventId``.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

import requests

from shared.component_identity import DesktopComponentIdentity
from shared.desktop_paths import get_desktop_path_layout
from shared.release_keys import trusted_keys
from shared.release_manifest import OfferRefused, VerifiedOffer, verify_offer
from shared.runtime_support import is_frozen, runtime_base_dir
from shared.update_files import (
    UpdatePaths,
    consume_marker,
    last_boot_epoch,
    parse_utc_iso,
    read_json,
    setup_is_running,
    utc_now_iso,
    write_boot_ok,
    write_json_atomic,
)
from shared.update_versions import compare_versions, installed_version_text, parse_version
from shared.update_wrapper import (
    HelperLaunchError,
    build_install_script,
    launch_hidden_powershell,
    setup_image_ps_re,
    setup_log_path,
)

CAPABILITIES = "signed-v1"
STARTUP_RECHECK_TIMEOUT_SEC = 5
FALLBACK_PENDING_SEC = 24 * 3600
FALLBACK_DOOR_IDLE_SEC = 15 * 60
FALLBACK_TICK_MS = 5 * 60 * 1000
RESULT_RESCAN_MS = 30 * 1000
RESULT_RESCAN_WINDOW_SEC = 10 * 60
OUTBOX_MAX = 50
# Results after which a version is never auto-installed again (design 7 loop guard).
# Anything else (health_timeout, interrupted, no result, Setup exit) gets one retry.
_BAN_REASONS = {"crash", "after_copy_failed", "setup_failed", "copy_failed", "post_install_failed", "restore_failed"}
TELEMETRY_RESULTS = {"PENDING", "INSTALLED", "ROLLED_BACK", "ABORTED", "VERIFY_FAILED", "DOWNLOAD_FAILED"}
# GetTickCount64-derived boot times drift by a second or two between reads.
_BOOT_EPOCH_SLACK_SEC = 120
# Delays before retrying a FAILED update check: 60 s, 5 min, then 15 min until one succeeds.
_CHECK_RETRY_DELAYS_SEC = (60, 5 * 60, 15 * 60)
_CHUNK = 256 * 1024


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


def _runtime_version_payload(component: DesktopComponentIdentity) -> Dict[str, Any]:
    base = runtime_base_dir()
    version_data = read_json(base / "version.json") or {}
    if version_data:
        return version_data
    if not is_frozen():
        update_data = read_json(base / "update.json") or {}
        component_data = update_data.get(component.component_id)
        if isinstance(component_data, dict):
            return component_data
    return {}


def _resolve_install_root(identity: DesktopComponentIdentity) -> Path:
    """``{app}``: the parent of ``current\\`` in a frozen build."""
    if is_frozen():
        return runtime_base_dir().parent

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


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_matches(path: Path, *, size: int, sha256: str) -> bool:
    try:
        return path.is_file() and path.stat().st_size == size and file_sha256(path) == sha256
    except OSError:
        return False


class DownloadCancelled(Exception):
    pass


class DownloadRefused(Exception):
    """The bytes arrived but are not the signed installer (size or SHA-256): VERIFY_FAILED."""


class InstallRefused(RuntimeError):
    """The install was not started; the app keeps running."""


class UpdateInstallStarted(Exception):
    """Raised from the app constructor when the start-up gate started the update wrapper:
    the entry point returns normally (a clean exit, not a crash) so the wrapper can run."""


@dataclass
class UpdateStatus:
    current_version: str = "0.0.0"
    current_codename: str = ""

    latest_version: Optional[str] = None
    latest_codename: Optional[str] = None
    release_date: Optional[str] = None
    available_until: Optional[str] = None
    size_bytes: Optional[int] = None
    release_notes: Optional[str] = None
    download_url: Optional[str] = None
    min_compatible_version: Optional[str] = None
    rollback: bool = False

    update_available: bool = False
    downloaded: bool = False
    download_path: Optional[str] = None
    downloading: bool = False
    progress_percent: Optional[int] = None

    # Why an offer was refused (signature, mismatch, unsigned): shown on the Update page.
    verify_error: Optional[str] = None
    # Set when the loop guard stopped auto-install of latest_version (manual still possible).
    auto_install_blocked: bool = False
    auto_install_blocked_reason: Optional[str] = None
    pending_since: Optional[float] = None
    # The installer's last result as last read from last_update.json.
    last_result: Optional[Dict[str, Any]] = None
    installing: bool = False

    last_check_at: float = 0.0
    last_error: Optional[str] = None

    current_release_id: str = "dev"
    latest_release: Optional[Dict[str, Any]] = None
    download_progress: Optional[int] = None
    progress: Optional[int] = None


class UpdateStateStore:
    """``{app}\\state\\update_state.json`` -- read-modify-write under one lock."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()

    def load(self) -> Dict[str, Any]:
        with self._lock:
            data = read_json(self.path) or {}
            data.setdefault("schema", 1)
            data.setdefault("versions", {})
            data.setdefault("outbox", [])
            data.setdefault("reported", [])
            return data

    def update(self, fn: Callable[[Dict[str, Any]], Any]) -> Any:
        with self._lock:
            data = self.load()
            result = fn(data)
            write_json_atomic(self.path, data)
            return result

    def install_id(self) -> str:
        def ensure(d: Dict[str, Any]) -> str:
            if not d.get("installId"):
                d["installId"] = uuid.uuid4().hex
            return d["installId"]

        with self._lock:
            existing = self.load().get("installId")
            return existing if existing else self.update(ensure)


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
        install_root: Optional[Path] = None,
        pc_key_provider: Optional[Callable[[], Optional[str]]] = None,
        door_idle_sec_provider: Optional[Callable[[], Optional[float]]] = None,
        keys_provider: Callable[[], Mapping[str, str]] = trusted_keys,
        auto_install_allowed: Optional[bool] = None,
        launcher: Callable[..., int] = launch_hidden_powershell,
        setup_running: Optional[Callable[[], bool]] = None,
        clock: Callable[[], float] = time.time,
        boot_epoch: Callable[[], Optional[float]] = last_boot_epoch,
    ) -> None:
        self.component = component
        self.app = app
        self.cfg = cfg
        self.logger = logger
        self._api_factory = api_factory
        self._pc_key_provider = pc_key_provider
        self._door_idle_sec_provider = door_idle_sec_provider
        self._keys_provider = keys_provider
        # Start-up and 24 h auto-install only in a frozen build: a source run must never
        # launch a real Setup by itself. Tests pass True.
        # A frozen exe outside {app}\current (a copied folder, a test build) never
        # auto-installs either: the wrapper would relaunch an exe that is not there.
        if auto_install_allowed is None:
            auto_install_allowed = is_frozen() and runtime_base_dir().name.lower() == "current"
        self._auto_install_allowed = bool(auto_install_allowed)
        self._launcher = launcher
        # Only this component's own Setup counts (an Access install ignores a TV Setup).
        self._setup_running = setup_running or (lambda: setup_is_running(target=component.component_id))
        self._clock = clock
        self._boot_epoch = boot_epoch

        self._lock = threading.RLock()
        self._running = False
        self._after_id: Optional[Any] = None
        self._fallback_after_id: Optional[Any] = None
        self._worker_running = False
        self._token: Optional[str] = None
        self._force_download_once = False
        self._check_fail_streak = 0
        self._cancel_event = threading.Event()
        self._install_lock = threading.Lock()
        self._outbox_lock = threading.Lock()
        self._session = requests.Session()

        self.install_root = Path(install_root) if install_root is not None else _resolve_install_root(component)
        self.paths = UpdatePaths(self.install_root)
        self.state = UpdateStateStore(self.paths.update_state)
        self._result_scan_deadline: float = 0.0
        self._boot_ok_written = False

        self.status = UpdateStatus(
            current_version=self.get_current_version(),
            current_codename=self.get_current_codename(),
            current_release_id=self.get_current_release_id(),
        )
        self._notified_version: Optional[str] = None
        self._last_progress_emit_at: float = 0.0
        self._last_progress_emit_pct: Optional[int] = None
        self._refresh_status_from_state()

    # ------------------------------------------------------------------ identity

    def get_current_version(self) -> str:
        """The installed version (``x.y.z[-pre]``) from version.json, else ``0.0.0``."""
        try:
            data = _runtime_version_payload(self.component)
            v = installed_version_text(data.get("version") or data.get("releaseId") or "")
            return v if parse_version(v) else "0.0.0"
        except Exception:
            return "0.0.0"

    def get_current_codename(self) -> str:
        try:
            return _safe_str(_runtime_version_payload(self.component).get("codename"), "")
        except Exception:
            return ""

    def get_current_release_id(self) -> str:
        try:
            data = _runtime_version_payload(self.component)
            rid = _safe_str(data.get("releaseId") or data.get("release_id") or data.get("version") or "", "")
            return rid or "dev"
        except Exception:
            return "dev"

    @property
    def target(self) -> str:
        return self.component.component_id

    def _platform(self) -> str:
        return _safe_str(getattr(self.cfg, "update_platform", "WINDOWS"), "WINDOWS").upper()

    def _channel(self) -> str:
        return _safe_str(getattr(self.cfg, "update_channel", "stable"), "stable").lower()

    def _interval_ms(self) -> int:
        from app.core.config import update_check_interval_sec

        return update_check_interval_sec(getattr(self.cfg, "update_check_interval_sec", None)) * 1000

    def _auto_download(self) -> bool:
        return bool(getattr(self.cfg, "update_auto_download_zip", True))

    def _log(self, level: str, msg: str, *args: Any) -> None:
        try:
            getattr(self.logger, level)("[Update:%s] " + msg, self.target, *args)
        except Exception:
            pass

    def _notify(self) -> None:
        try:
            self.app.after(0, lambda: self.app.on_update_status_changed(self.status))
        except Exception:
            pass

    # ------------------------------------------------------------------ scheduling

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
                self._log(
                    "info",
                    "started (platform=%s channel=%s version=%s installRoot=%s autoInstall=%s)",
                    self._platform(),
                    self._channel(),
                    self.status.current_version,
                    str(self.install_root),
                    self._auto_install_allowed,
                )
                self._schedule_fallback(FALLBACK_TICK_MS)
            if check_now:
                self._schedule_next(0)
            elif self._after_id is None:
                self._schedule_next(self._interval_ms())

    def stop(self) -> None:
        with self._lock:
            self._running = False
            self._token = None
            self._force_download_once = False
            self._cancel_event.set()
            for attr in ("_after_id", "_fallback_after_id"):
                after_id = getattr(self, attr)
                if after_id is not None:
                    try:
                        self.app.after_cancel(after_id)
                    except Exception:
                        pass
                    setattr(self, attr, None)

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

    def _schedule_fallback(self, delay_ms: int) -> None:
        with self._lock:
            if not self._running:
                return
            if self._fallback_after_id is not None:
                try:
                    self.app.after_cancel(self._fallback_after_id)
                except Exception:
                    pass
            self._fallback_after_id = self.app.after(delay_ms, self._fallback_timer)

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
            self._cancel_event.clear()

        def work() -> None:
            ok = False
            try:
                ok = self._run_check_and_download(token=token, force_download=force_download) is not False
                self.consume_results()
                self.flush_outbox(token=token)
            finally:
                with self._lock:
                    self._worker_running = False
                self._after_check(ok)

        threading.Thread(target=work, daemon=True, name=f"{self.target}-update-check").start()

    def _after_check(self, ok: bool) -> None:
        """After a failed check, try again soon (60 s, 5 min, then every 15 min) instead of
        waiting the whole interval _tick already scheduled; a success resets the streak."""
        with self._lock:
            self._check_fail_streak = 0 if ok else self._check_fail_streak + 1
            streak = self._check_fail_streak
        if not streak:
            return
        delay_sec = _CHECK_RETRY_DELAYS_SEC[min(streak, len(_CHECK_RETRY_DELAYS_SEC)) - 1]
        delay_ms = min(delay_sec * 1000, self._interval_ms())
        try:
            self.app.after(0, lambda: self._schedule_next(delay_ms))
        except Exception:
            pass

    # ------------------------------------------------------------------ check

    def _fetch_offer(self, *, token: str, timeout: int) -> Dict[str, Any]:
        api = self._api_factory()
        return api.get_latest_software_release(
            token=token,
            platform=self._platform(),
            channel=self._channel(),
            current_version=self.get_current_version(),
            target=self.target,
            release_id=None,
            capabilities=CAPABILITIES,
            timeout=timeout,
        )

    def _verify(self, offer: Mapping[str, Any]) -> VerifiedOffer:
        return verify_offer(
            offer,
            target=self.target,
            platform=self._platform(),
            channel=self._channel(),
            installed_version=self.get_current_version(),
            keys=self._keys_provider(),
        )

    def _run_check_and_download(self, *, token: str, force_download: bool = False) -> Optional[bool]:
        """False when the check failed (logged); None otherwise."""
        try:
            self.status.current_version = self.get_current_version()
            self.status.current_codename = self.get_current_codename()
            self.status.current_release_id = self.get_current_release_id()
            try:
                offer = self._fetch_offer(token=token, timeout=20)
            except Exception as exc:
                raise RuntimeError(f"update check failed: {exc}") from exc
            self.status.last_check_at = self._clock()
            self.status.last_error = None

            if not isinstance(offer, dict) or not bool(offer.get("shouldUpdate", False)):
                no_release = isinstance(offer, dict) and bool(offer.get("noRelease"))
                self._discard_pending("no release offered (404)" if no_release else "server says up to date")
                self._set_no_update(offer if isinstance(offer, dict) and not no_release else None)
                return None

            try:
                verified = self._verify(offer)
            except OfferRefused as refused:
                self._discard_pending(f"offer refused: {refused.code}")
                if not refused.is_verify_failure:
                    self._set_no_update(offer)
                    return None
                self._on_offer_refused(offer, refused)
                return None

            self._accept_offer(offer, verified)
            pending = self._pending()
            if pending and pending.get("downloaded") and self._pending_file_ok(pending):
                self._set_status_from_pending(pending, offer)
                return None
            if not self._auto_download() and not force_download:
                self._set_status_from_pending(pending, offer)
                return None
            self._download(verified)
            self._set_status_from_pending(self._pending(), offer)
            self._cleanup_downloads(keep_version=verified.version)
            return None
        except DownloadCancelled:
            self._log("info", "download cancelled")
            return None
        except Exception as exc:
            msg = str(exc)
            self.status.last_error = msg
            self._log("warning", "failed: %s", msg)
            try:
                self.app.after(0, lambda: self.app.on_update_error(msg))
            except Exception:
                pass
            return False
        finally:
            self._set_downloading(False, None)

    def _on_offer_refused(self, offer: Mapping[str, Any], refused: OfferRefused) -> None:
        version = _safe_str(offer.get("version"), "?")
        self._log("warning", "refusing offer %s: %s (%s)", version, refused.message, refused.code)
        self.status.update_available = False
        self.status.downloaded = False
        self.status.download_path = None
        self.status.latest_version = version
        self.status.verify_error = refused.message
        self.status.latest_release = dict(offer)
        self.emit_event(
            "VERIFY_FAILED",
            to_version=version,
            detail=f"{refused.code}: {refused.message}",
            once_key=f"VERIFY_FAILED|{version}|{refused.code}",
        )
        self._notify()

    def _accept_offer(self, offer: Mapping[str, Any], verified: VerifiedOffer) -> None:
        now = self._clock()

        def apply(d: Dict[str, Any]) -> None:
            pending = d.get("pending") if isinstance(d.get("pending"), dict) else None
            same = bool(
                pending
                and pending.get("version") == verified.version
                and pending.get("signedManifest") == verified.manifest_text
            )
            if not same:
                pending = {"firstSeenAt": now, "downloaded": False}
            pending.update(verified.to_json())
            pending["releaseNotes"] = _safe_str(offer.get("releaseNotes") or offer.get("notes"), "")
            pending["codename"] = _safe_str(offer.get("codename"), "")
            pending["publishedAt"] = _safe_str(offer.get("publishedAt") or offer.get("releaseDate"), "")
            pending["availableUntil"] = _safe_str(offer.get("availableUntil"), "")
            pending["path"] = str(self._download_path(verified))
            d["pending"] = pending

        if self._pending() and self._pending().get("version") != verified.version:
            self._discard_pending(f"replaced by {verified.version}")
        self.state.update(apply)
        self.status.verify_error = None

    # ------------------------------------------------------------------ pending

    def _pending(self) -> Optional[Dict[str, Any]]:
        pending = self.state.load().get("pending")
        return pending if isinstance(pending, dict) and pending.get("version") else None

    def _pending_file_ok(self, pending: Mapping[str, Any]) -> bool:
        try:
            return _file_matches(
                Path(str(pending.get("path") or "")),
                size=int(pending.get("installerSize") or 0),
                sha256=str(pending.get("installerSha256") or ""),
            )
        except Exception:
            return False

    def _discard_pending(self, why: str) -> None:
        pending = self._pending()
        if not pending:
            return
        self._log("info", "discarding pending update %s: %s", pending.get("version"), why)

        def drop(d: Dict[str, Any]) -> None:
            d.pop("pending", None)

        self.state.update(drop)
        try:
            folder = Path(str(pending.get("path") or "")).parent
            if folder.is_dir() and self.paths.downloads_dir in folder.parents:
                shutil.rmtree(folder, ignore_errors=True)
        except Exception:
            pass

    def _download_path(self, verified: VerifiedOffer) -> Path:
        return (
            self.paths.downloads_dir
            / self.target
            / _lower(self._channel())
            / verified.version
            / verified.installer_name
        )

    def _set_no_update(self, offer: Optional[Mapping[str, Any]]) -> None:
        self.status.update_available = False
        self.status.downloaded = False
        self.status.download_path = None
        self.status.verify_error = None
        self.status.rollback = False
        self.status.auto_install_blocked = False
        self.status.auto_install_blocked_reason = None
        self.status.pending_since = None
        self.status.latest_release = dict(offer) if offer else None
        self.status.latest_version = _safe_str((offer or {}).get("version"), "") or None
        self._notify()

    def _set_status_from_pending(self, pending: Optional[Mapping[str, Any]], offer: Optional[Mapping[str, Any]] = None) -> None:
        if not pending:
            self._set_no_update(offer)
            return
        version = str(pending.get("version"))
        downloaded = bool(pending.get("downloaded")) and Path(str(pending.get("path") or "")).is_file()
        self.status.update_available = True
        self.status.latest_version = version
        self.status.latest_codename = _safe_str(pending.get("codename"), "")
        self.status.release_date = _safe_str(pending.get("publishedAt"), "") or None
        self.status.available_until = _safe_str(pending.get("availableUntil"), "") or None
        self.status.release_notes = _safe_str(pending.get("releaseNotes"), "")
        self.status.size_bytes = int(pending.get("installerSize") or 0) or None
        self.status.download_url = _safe_str(pending.get("installerUrl"), "") or None
        self.status.rollback = bool(pending.get("rollback"))
        self.status.downloaded = downloaded
        self.status.download_path = str(pending.get("path")) if downloaded else None
        self.status.pending_since = pending.get("firstSeenAt")
        self.status.verify_error = None
        ban = self._ban_reason(version)
        self.status.auto_install_blocked = ban is not None
        self.status.auto_install_blocked_reason = ban
        if offer is not None:
            self.status.latest_release = dict(offer)
        self._notify()
        if downloaded and version != self._notified_version:
            self._notified_version = version
            try:
                self.app.after(0, lambda: self.app.on_update_ready(self.status))
            except Exception:
                pass

    def _refresh_status_from_state(self) -> None:
        try:
            data = self.state.load()
            last = data.get("lastResult")
            self.status.last_result = last if isinstance(last, dict) else None
            pending = data.get("pending") if isinstance(data.get("pending"), dict) else None
            if pending:
                self.status.update_available = True
                self.status.latest_version = str(pending.get("version"))
                self.status.downloaded = bool(pending.get("downloaded"))
                self.status.download_path = str(pending.get("path")) if pending.get("downloaded") else None
                self.status.release_notes = _safe_str(pending.get("releaseNotes"), "")
                self.status.size_bytes = int(pending.get("installerSize") or 0) or None
                self.status.rollback = bool(pending.get("rollback"))
                self.status.pending_since = pending.get("firstSeenAt")
                ban = self._ban_reason(str(pending.get("version")))
                self.status.auto_install_blocked = ban is not None
                self.status.auto_install_blocked_reason = ban
        except Exception:
            pass

    # ------------------------------------------------------------------ download

    def cancel_download(self) -> None:
        """Abort a running download (D37) and delete the downloaded installer."""
        self._cancel_event.set()
        pending = self._pending()
        if pending:
            path = Path(str(pending.get("path") or ""))
            for p in (path, path.with_name(path.name + ".part")):
                try:
                    p.unlink(missing_ok=True)
                except OSError as exc:
                    self._log("warning", "cancel_download delete failed: %s", exc)

            def mark(d: Dict[str, Any]) -> None:
                if isinstance(d.get("pending"), dict):
                    d["pending"]["downloaded"] = False

            self.state.update(mark)
            self._log("info", "download cancelled / deleted for %s", pending.get("version"))
        with self._lock:
            self.status.downloaded = False
            self.status.download_path = None
            self.status.downloading = False
            self.status.progress_percent = None
            self.status.progress = None
            self.status.download_progress = None
        self._notify()

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
            if downloading and progress is not None and (now - self._last_progress_emit_at) < 0.25:
                return
            self._last_progress_emit_at = now
            self._last_progress_emit_pct = progress
            self._notify()
        except Exception:
            pass

    def _download(self, verified: VerifiedOffer) -> Path:
        final = self._download_path(verified)
        part = final.with_name(final.name + ".part")
        final.parent.mkdir(parents=True, exist_ok=True)

        if final.exists():
            if _file_matches(final, size=verified.installer_size, sha256=verified.installer_sha256):
                self._mark_downloaded(verified, final)
                return final
            self._log("warning", "cached %s does not match the signed SHA-256; downloading again", final)
            final.unlink(missing_ok=True)

        self._log("info", "downloading %s -> %s", verified.installer_url, final)
        self._set_downloading(True, 0)
        try:
            r = self._session.get(verified.installer_url, stream=True, timeout=300)
        except Exception as exc:
            self._report_download_failed(verified, f"request failed: {exc}")
            raise
        if r.status_code < 200 or r.status_code >= 300:
            self._report_download_failed(verified, f"HTTP {r.status_code}")
            raise RuntimeError(f"Download failed: HTTP {r.status_code} -> {verified.installer_url}")

        expected = verified.installer_size
        h = hashlib.sha256()
        done = 0
        last_pct: Optional[int] = None
        try:
            with part.open("wb") as f:
                for chunk in r.iter_content(chunk_size=_CHUNK):
                    if self._cancel_event.is_set():
                        raise DownloadCancelled()
                    if not chunk:
                        continue
                    done += len(chunk)
                    if done > expected:
                        raise DownloadRefused(f"server sent more than the signed {expected} bytes")
                    f.write(chunk)
                    h.update(chunk)
                    pct = int(done * 100 / expected)
                    if pct != last_pct:
                        last_pct = pct
                        self._set_downloading(True, pct)
            if done != expected:
                raise DownloadRefused(f"downloaded {done} bytes, the signed size is {expected}")
            if h.hexdigest() != verified.installer_sha256:
                raise DownloadRefused("downloaded file does not match the signed SHA-256")
            os.replace(part, final)
        except DownloadRefused as refused:
            part.unlink(missing_ok=True)
            self._log("error", "refusing download of %s: %s", verified.version, refused)
            self.status.verify_error = str(refused)
            self.emit_event(
                "VERIFY_FAILED",
                to_version=verified.version,
                detail=f"download: {refused}",
                once_key=f"VERIFY_FAILED|{verified.version}|download",
            )
            raise
        except DownloadCancelled:
            part.unlink(missing_ok=True)
            raise
        except Exception as exc:
            part.unlink(missing_ok=True)
            self._report_download_failed(verified, str(exc))
            raise
        finally:
            try:
                r.close()
            except Exception:
                pass
        self._mark_downloaded(verified, final)
        self._log("info", "downloaded and verified %s (%s bytes)", final, expected)
        return final

    def _report_download_failed(self, verified: VerifiedOffer, detail: str) -> None:
        self.emit_event(
            "DOWNLOAD_FAILED",
            to_version=verified.version,
            detail=detail,
            once_key=f"DOWNLOAD_FAILED|{verified.version}",
        )

    def _mark_downloaded(self, verified: VerifiedOffer, path: Path) -> None:
        now = self._clock()

        def mark(d: Dict[str, Any]) -> None:
            p = d.get("pending")
            if isinstance(p, dict) and p.get("version") == verified.version:
                p["downloaded"] = True
                p["downloadedAt"] = p.get("downloadedAt") or now
                p["path"] = str(path)

        self.state.update(mark)

    def _cleanup_downloads(self, *, keep_version: Optional[str]) -> None:
        """Delete every download except the pending version's folder (D35).

        Also removes the pre-v2 layout ``downloads\\<platform>\\<channel>\\*.exe``."""
        root = self.paths.downloads_dir
        if not root.is_dir():
            return
        keep = (root / self.target / _lower(self._channel()) / keep_version) if keep_version else None
        for dirpath, dirnames, filenames in os.walk(root, topdown=False):
            here = Path(dirpath)
            if keep is not None and (here == keep or keep in here.parents):
                continue
            for name in filenames:
                try:
                    (here / name).unlink()
                except OSError:
                    pass
            if here != root and (keep is None or here not in keep.parents):
                try:
                    here.rmdir()
                except OSError:
                    pass

    # ------------------------------------------------------------------ loop guard

    def _retry_wait_reason(self, version: str) -> Optional[str]:
        """A struck (not banned) version is retried automatically only at the NEXT start-up
        of the PC (design 7: "one automatic retry at the next start-up"), not when Setup
        relaunches the old version seconds later -- or, on a PC never switched off, 24 h
        after the failure."""
        entry = (self.state.load().get("versions") or {}).get(version) or {}
        if not entry.get("strikes") or entry.get("banned"):
            return None
        failed_at = float(entry.get("lastFailureAt") or 0)
        if failed_at and self._clock() - failed_at >= FALLBACK_PENDING_SEC:
            return None
        failed_boot = entry.get("lastFailureBoot")
        boot = self._boot_epoch()
        if failed_boot is not None and boot is not None and boot > float(failed_boot) + _BOOT_EPOCH_SLACK_SEC:
            return None
        return "failed once; retried at the next PC start-up"

    def _ban_reason(self, version: str) -> Optional[str]:
        entry = (self.state.load().get("versions") or {}).get(version) or {}
        if entry.get("banned"):
            return _safe_str(entry.get("banReason"), "failed before")
        return None

    def _record_failure(self, d: Dict[str, Any], version: str, reason: str) -> None:
        versions = d.setdefault("versions", {})
        entry = versions.setdefault(version, {})
        entry["lastFailureAt"] = self._clock()
        entry["lastFailureBoot"] = self._boot_epoch()
        if reason in _BAN_REASONS:
            entry["banned"] = True
            entry["banReason"] = reason
        else:
            entry["strikes"] = int(entry.get("strikes") or 0) + 1
            if entry["strikes"] >= 2:
                entry["banned"] = True
                entry["banReason"] = f"{reason} (twice)"
        if entry.get("banned"):
            self._log("warning", "version %s will not be installed automatically again: %s", version, entry["banReason"])

    # ------------------------------------------------------------------ results

    def consume_results(self, *, at_boot: bool = False) -> Optional[Dict[str, Any]]:
        """Read ``last_update.json`` once, apply the loop guard, report it (design 7 Result).

        At boot also closes an install attempt that left no result at all (Setup never ran
        its code): counted as one strike, never more than one retry."""
        result = read_json(self.paths.last_update)
        processed: Optional[Dict[str, Any]] = None
        if result is not None:
            processed = self._apply_result(result, consume_marker(result))
            try:
                os.replace(self.paths.last_update, self.paths.last_update_consumed)
            except OSError:
                pass
        if at_boot and processed is None:
            self._close_attempt_without_result()
        self._refresh_status_from_state()
        if processed is not None:
            self._notify()
        return processed

    @staticmethod
    def _result_versions(kind: str, raw_from: str, raw_to: str, attempt: Optional[Mapping[str, Any]]) -> Tuple[str, str]:
        """(version before the install, version the install tried) of one result.

        The writers name the TRANSITION (L2 update_safety.iss UpdWriteLastUpdate, and this
        lane's restore helper / wrapper): ``ROLLED_BACK`` from = the version that failed,
        to = the one restored; ``INSTALLED`` / ``ABORTED`` from = before, to = the version
        tried. The open install attempt, when there is one, names the tried version."""
        if kind == "ROLLED_BACK":
            before, tried = raw_to, raw_from
        else:
            before, tried = raw_from, raw_to
        if attempt and attempt.get("version") and str(attempt["version"]) in (raw_from, raw_to, ""):
            tried = str(attempt["version"])
            before = before if before and before != tried else _safe_str(attempt.get("from"), "")
        return before, tried

    def _apply_result(self, result: Dict[str, Any], marker: str) -> Optional[Dict[str, Any]]:
        """Apply one installer result exactly once (the check runs under the state lock, so
        the 30 s rescan and the check thread cannot both count it). None when already done."""
        kind = _safe_str(result.get("result"), "").upper()
        reason = _lower(result.get("reason"))
        raw_from = _safe_str(result.get("from"), "")
        raw_to = _safe_str(result.get("to"), "")
        now = self._clock()
        installed = self.get_current_version()
        detail_parts = [p for p in (f"reason={reason}" if reason else "", _safe_str(result.get("log"), "")) if p]
        outcome: Dict[str, Any] = {}

        def apply(d: Dict[str, Any]) -> None:
            if d.get("lastConsumed") == marker:
                return
            attempt = d.get("attempt") if isinstance(d.get("attempt"), dict) else None
            before, tried = self._result_versions(kind, raw_from, raw_to, attempt)
            if attempt and attempt.get("version") == tried:
                started = float(attempt.get("at") or 0)
                if started:
                    took = max(0.0, now - started)
                    detail_parts.append(f"mode={attempt.get('mode')} took={took:.0f}s")
                    self._log("info", "install %s -> %s (%s) took %.0f s from launch to result", before, tried, attempt.get("mode"), took)
            d.pop("attempt", None)
            if kind == "INSTALLED":
                pending = d.get("pending")
                if isinstance(pending, dict) and pending.get("version") == tried:
                    d.pop("pending", None)
            elif kind == "ABORTED" and reason == "same_version":
                pass
            elif kind in ("ROLLED_BACK", "ABORTED") and tried and tried != installed:
                self._record_failure(d, tried, reason or "unknown")
            d["lastConsumed"] = marker
            d["lastResult"] = {
                "result": kind or "UNKNOWN",
                "from": before,
                "to": tried,
                "reason": reason,
                "at": _safe_str(result.get("at"), "") or utc_now_iso(now),
                "installedNow": installed,
            }
            outcome.update(before=before, tried=tried)

        self.state.update(apply)
        if not outcome:
            return None
        before, tried = outcome["before"], outcome["tried"]
        self._log("info", "installer result: %s (tried %s, before %s) reason=%s; running %s", kind, tried, before, reason or "-", installed)
        telemetry_kind = kind if kind in TELEMETRY_RESULTS else "ABORTED"
        # Telemetry always says fromVersion = before the install, toVersion = the version tried.
        self.emit_event(
            telemetry_kind,
            from_version=before,
            to_version=tried or installed,
            detail="; ".join(detail_parts) or None,
            occurred_at=_safe_str(result.get("at"), "") or None,
            id_seed=marker,
        )
        if kind == "INSTALLED":
            self._cleanup_downloads(keep_version=(self._pending() or {}).get("version"))
        return result

    def _close_attempt_without_result(self) -> None:
        attempt = self.state.load().get("attempt")
        if not isinstance(attempt, dict) or not attempt.get("version"):
            return
        version = str(attempt["version"])
        installed = self.get_current_version()
        if installed == version:
            return  # Setup writes INSTALLED after our boot_ok: the rescans pick it up.
        if self._setup_running():
            return
        self._log("warning", "install of %s left no result (still on %s): counting one failed attempt", version, installed)

        def apply(d: Dict[str, Any]) -> None:
            d.pop("attempt", None)
            self._record_failure(d, version, "no_result")
            d["lastResult"] = {
                "result": "ABORTED",
                "from": installed,
                "to": version,
                "reason": "no_result",
                "at": utc_now_iso(self._clock()),
                "installedNow": installed,
            }

        self.state.update(apply)
        self.emit_event(
            "ABORTED",
            from_version=installed,
            to_version=version,
            detail="reason=no_result (Setup left no result file)",
            id_seed=f"no_result|{version}|{attempt.get('at')}",
        )

    def _close_attempt_installed_without_result(self) -> None:
        """End of the rescan window: we run the attempted version and Setup wrote nothing
        (e.g. an interactive install): report it installed."""
        attempt = self.state.load().get("attempt")
        if not isinstance(attempt, dict) or attempt.get("version") != self.get_current_version():
            return
        version = str(attempt["version"])

        def apply(d: Dict[str, Any]) -> None:
            d.pop("attempt", None)
            pending = d.get("pending")
            if isinstance(pending, dict) and pending.get("version") == version:
                d.pop("pending", None)

        self.state.update(apply)
        self.emit_event(
            "INSTALLED",
            from_version=_safe_str(attempt.get("from"), ""),
            to_version=version,
            detail="no installer result file; running the new version",
            id_seed=f"installed_no_result|{version}|{attempt.get('at')}",
        )

    # ------------------------------------------------------------------ boot

    def on_local_api_ready(self) -> None:
        """Called on the main loop once the local API listens: write the health marker
        Setup waits for, then look for the installer's result for 10 minutes. Once per
        process (a local API restart calls it again)."""
        if self._boot_ok_written:
            return
        try:
            payload = write_boot_ok(self.paths, version=self.get_current_version())
            self._boot_ok_written = True
            self._log("info", "boot_ok written (version=%s pid=%s)", payload["version"], payload["pid"])
        except Exception as exc:
            self._log("error", "could not write boot_ok.json: %s", exc)
        self._result_scan_deadline = self._clock() + RESULT_RESCAN_WINDOW_SEC
        self._rescan_results()

    def _rescan_results(self) -> None:
        def work() -> None:
            try:
                self.consume_results()
                pending = self._pending()
                self._cleanup_downloads(keep_version=pending.get("version") if pending else None)
                if self._clock() >= self._result_scan_deadline:
                    self._close_attempt_installed_without_result()
                token = self._token or ""
                if token:
                    self.flush_outbox(token=token)
            except Exception as exc:
                self._log("warning", "result rescan failed: %s", exc)

        threading.Thread(target=work, daemon=True, name=f"{self.target}-update-result").start()
        if self._clock() < self._result_scan_deadline:
            try:
                self.app.after(RESULT_RESCAN_MS, self._rescan_results)
            except Exception:
                pass

    # ------------------------------------------------------------------ install

    def can_install_now(self) -> Tuple[bool, str]:
        pending = self._pending()
        if not pending:
            return False, "No update available."
        if not pending.get("downloaded"):
            return False, "Update not downloaded yet."
        if not Path(str(pending.get("path") or "")).is_file():
            return False, "Downloaded file is missing."
        if self.status.installing:
            return False, "An install is already starting."
        return True, "OK"

    def launch_install(self, *, mode: str = "manual") -> int:
        """Verify the pending installer again and start the wrapper.

        Returns the wrapper pid. Raises InstallRefused (app keeps running) when anything is
        wrong. The caller quits the app ONLY after this returns (D1)."""
        if not self._install_lock.acquire(blocking=False):
            raise InstallRefused("An install is already starting.")
        try:
            pending = self._pending()
            if not pending:
                raise InstallRefused("No update available.")
            if not pending.get("downloaded"):
                raise InstallRefused("Update not downloaded yet.")
            installer = Path(str(pending.get("path") or ""))
            # The manifest again (version still applies to what is installed now) ...
            try:
                verified = self._verify(
                    {
                        "version": pending.get("version"),
                        "signedManifest": pending.get("signedManifest"),
                        "manifestSignature": pending.get("manifestSignature"),
                        "signingKeyId": pending.get("signingKeyId"),
                        "installer": {"url": pending.get("installerUrl")},
                    }
                )
            except OfferRefused as refused:
                self._discard_pending(f"no longer valid: {refused.code}")
                raise InstallRefused(f"Update refused: {refused.message}")
            # ... and the file right before launch (D11, D12).
            if not _file_matches(installer, size=verified.installer_size, sha256=verified.installer_sha256):
                try:
                    installer.unlink(missing_ok=True)
                except OSError:
                    pass

                def unmark(d: Dict[str, Any]) -> None:
                    if isinstance(d.get("pending"), dict):
                        d["pending"]["downloaded"] = False

                self.state.update(unmark)
                self.emit_event(
                    "VERIFY_FAILED",
                    to_version=verified.version,
                    detail="installer changed on disk after download; deleted",
                    once_key=f"VERIFY_FAILED|{verified.version}|disk",
                )
                self._refresh_status_from_state()
                self._notify()
                raise InstallRefused("The downloaded installer does not match the signed release; it was deleted.")

            from_version = self.get_current_version()
            now = self._clock()
            setup_log = setup_log_path(self.install_root, verified.version, now=now)
            script = build_install_script(
                setup_image_re=setup_image_ps_re(self.target),
                app_pid=os.getpid(),
                installer=installer,
                install_root=self.install_root,
                exe_name=self.component.main_exe_name,
                from_version=from_version,
                to_version=verified.version,
                setup_log=setup_log,
                wrapper_log=self.paths.logs_dir / "update-wrapper.log",
            )
            previous_attempt: Dict[str, Any] = {}

            def record(d: Dict[str, Any]) -> None:
                if isinstance(d.get("attempt"), dict):
                    previous_attempt.update(d["attempt"])
                d["attempt"] = {"version": verified.version, "from": from_version, "at": now, "mode": mode, "log": str(setup_log)}

            self.state.update(record)
            try:
                pid = self._launcher(script, cwd=self.paths.state_dir)
            except (HelperLaunchError, Exception) as exc:
                def undo(d: Dict[str, Any]) -> None:
                    if previous_attempt:
                        d["attempt"] = previous_attempt
                    else:
                        d.pop("attempt", None)

                self.state.update(undo)
                self._log("error", "could not start the update wrapper: %s", exc)
                raise InstallRefused(f"Could not start the installer: {exc}")
            self.status.installing = True
            self._log(
                "info",
                "update wrapper started (pid=%s, %s -> %s, mode=%s, setup log %s); the app now exits",
                pid,
                from_version,
                verified.version,
                mode,
                setup_log,
            )
            self.emit_event(
                "PENDING",
                from_version=from_version,
                to_version=verified.version,
                detail=f"install started mode={mode}",
                id_seed=f"pending|{verified.version}|{now}",
                flush=False,
            )
            return pid
        finally:
            self._install_lock.release()

    def _recheck_still_offered(self, pending: Mapping[str, Any], token: str) -> str:
        """``"offered"`` / ``"gone"`` / ``"unreachable"`` within 5 s (design 7 auto-install)."""
        if not token:
            return "unreachable"
        try:
            offer = self._fetch_offer(token=token, timeout=STARTUP_RECHECK_TIMEOUT_SEC)
        except Exception as exc:
            self._log("info", "re-check before install did not answer (%s); installing the signed pending update", exc)
            return "unreachable"
        if not isinstance(offer, dict) or not offer.get("shouldUpdate"):
            return "gone"
        if _safe_str(offer.get("version"), "") != pending.get("version"):
            return "gone"
        if offer.get("signedManifest") != pending.get("signedManifest"):
            return "gone"
        return "offered"

    def _auto_install(self, *, token: str, mode: str) -> bool:
        """Shared by the start-up gate and the 24 h fallback. True when the wrapper started."""
        pending = self._pending()
        if not pending:
            return False
        version = str(pending.get("version"))
        ban = self._ban_reason(version) or self._retry_wait_reason(version)
        if ban:
            self._log("info", "pending %s not auto-installed: %s (Update page button still works)", version, ban)
            return False
        if not pending.get("downloaded") or not self._pending_file_ok(pending):
            return False
        if self._setup_running():
            self._log("info", "a Setup is already running; not auto-installing")
            return False
        verdict = self._recheck_still_offered(pending, token)
        if verdict == "gone":
            self._discard_pending("paused, withdrawn or replaced on the server")
            self._refresh_status_from_state()
            self._set_no_update(None)
            return False
        try:
            self.launch_install(mode=mode)
            return True
        except InstallRefused as exc:
            self._log("warning", "auto-install (%s) not started: %s", mode, exc)
            return False

    def startup_gate(self, *, token: Optional[str]) -> bool:
        """At process start, before device / ULTRA / sync work (O1, D25).

        Consumes the installer's result first. Then, in a frozen build, installs a verified
        pending update. True = the wrapper is running and the caller must exit now.
        Without a pending update no network call is made."""
        started = time.monotonic()
        try:
            self.consume_results(at_boot=True)
        except Exception as exc:
            self._log("warning", "start-up result check failed: %s", exc)
        if not self._auto_install_allowed or not bool(getattr(self.cfg, "update_enabled", True)):
            return False
        pending = self._pending()
        if not pending:
            return False
        try:
            launched = self._auto_install(token=_safe_str(token, ""), mode="startup")
        except Exception as exc:
            self._log("error", "start-up auto-install failed: %s", exc)
            launched = False
        self._log(
            "info",
            "start-up update gate: pending=%s launched=%s in %.1f s",
            pending.get("version"),
            launched,
            time.monotonic() - started,
        )
        return launched

    def _fallback_timer(self) -> None:
        self._schedule_fallback(FALLBACK_TICK_MS)
        token = _safe_str(self._token, "")

        def work() -> None:
            try:
                if self.fallback_due():
                    if self._auto_install(token=token, mode="fallback"):
                        self.app.after(500, self.app.quit_app)
            except Exception as exc:
                self._log("warning", "24 h fallback check failed: %s", exc)

        threading.Thread(target=work, daemon=True, name=f"{self.target}-update-fallback").start()

    def fallback_due(self) -> bool:
        """Pending for 24 h and no door event for 15 min (O1 fallback for always-on PCs)."""
        if not self._auto_install_allowed:
            return False
        pending = self._pending()
        if not pending or not pending.get("downloaded"):
            return False
        try:
            first_seen = float(pending.get("firstSeenAt") or 0)
        except (TypeError, ValueError):
            return False
        if not first_seen or self._clock() - first_seen < FALLBACK_PENDING_SEC:
            return False
        if self._door_idle_sec_provider is None:
            return True  # TV: no doors
        try:
            idle = self._door_idle_sec_provider()
        except Exception:
            return False
        # Unknown idle time is not idle: never install over a possible passage.
        return idle is not None and idle >= FALLBACK_DOOR_IDLE_SEC

    # ------------------------------------------------------------------ telemetry

    def _pc_key(self) -> str:
        key = None
        if self._pc_key_provider is not None:
            try:
                key = _safe_str(self._pc_key_provider(), "")
            except Exception:
                key = None
        if key:
            return key[:64]
        prefix = "tv" if self.target == "tv" else "install"
        return f"{prefix}-{self.state.install_id()}"[:64]

    def emit_event(
        self,
        result: str,
        *,
        to_version: str,
        from_version: Optional[str] = None,
        detail: Optional[str] = None,
        occurred_at: Optional[str] = None,
        once_key: Optional[str] = None,
        id_seed: Optional[str] = None,
        flush: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Queue one telemetry event (design 6.4). ``once_key``: never queue the same twice."""
        try:
            pc_key = self._pc_key()
            at = occurred_at or utc_now_iso(self._clock())
            seed = id_seed or once_key or f"{result}|{to_version}|{at}|{uuid.uuid4().hex}"
            event = {
                "eventId": str(uuid.uuid5(uuid.NAMESPACE_URL, f"monclub-update|{self.target}|{pc_key}|{result}|{seed}")),
                "target": self.target,
                "pcKey": pc_key,
                "pcName": (socket.gethostname() or "")[:128],
                "fromVersion": from_version if from_version is not None else self.get_current_version(),
                "toVersion": _safe_str(to_version, "") or self.get_current_version(),
                "result": result,
                "detail": (detail or "")[:500] or None,
                "occurredAt": at,
            }

            def queue(d: Dict[str, Any]) -> bool:
                reported: List[str] = d.setdefault("reported", [])
                if once_key and once_key in reported:
                    return False
                if once_key:
                    reported.append(once_key)
                    del reported[:-200]
                outbox: List[Dict[str, Any]] = d.setdefault("outbox", [])
                if any(e.get("eventId") == event["eventId"] for e in outbox):
                    return False
                outbox.append(event)
                del outbox[:-OUTBOX_MAX]
                return True

            if not self.state.update(queue):
                return None
            self._log("info", "telemetry queued: %s %s -> %s %s", result, event["fromVersion"], event["toVersion"], detail or "")
            if flush and self._token:
                token = self._token
                threading.Thread(target=lambda: self.flush_outbox(token=token), daemon=True,
                                 name=f"{self.target}-update-telemetry").start()
            return event
        except Exception as exc:
            self._log("warning", "telemetry not queued: %s", exc)
            return None

    def flush_outbox(self, *, token: str) -> int:
        """POST queued events; drop accepted (2xx) and refused (4xx but 408/429) ones.
        Returns how many left the outbox. An old backend answers 404: dropped, never piles up."""
        if not token or not self._outbox_lock.acquire(blocking=False):
            return 0
        sent = 0
        try:
            events = list(self.state.load().get("outbox") or [])
            if not events:
                return 0
            api = self._api_factory()
            for event in events:
                try:
                    code = int(api.post_software_update_event(token=token, event=event, timeout=10))
                except Exception as exc:
                    self._log("info", "telemetry not sent (will retry): %s", exc)
                    break
                if 500 <= code or code in (408, 429):
                    self._log("info", "telemetry HTTP %s (will retry)", code)
                    break
                if not (200 <= code < 300):
                    self._log("warning", "telemetry event %s dropped: HTTP %s", event.get("eventId"), code)
                event_id = event.get("eventId")

                def drop(d: Dict[str, Any]) -> None:
                    d["outbox"] = [e for e in (d.get("outbox") or []) if e.get("eventId") != event_id]

                self.state.update(drop)
                sent += 1
            return sent
        finally:
            self._outbox_lock.release()


__all__ = [
    "CAPABILITIES",
    "ComponentUpdateManager",
    "DownloadCancelled",
    "DownloadRefused",
    "InstallRefused",
    "UpdateInstallStarted",
    "UpdateStateStore",
    "UpdateStatus",
    "file_sha256",
]

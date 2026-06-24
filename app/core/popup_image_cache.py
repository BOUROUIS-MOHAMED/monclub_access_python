"""Shared popup image cache.

Single source of truth for:
  - Normalizing image references coming from the backend (relative paths,
    legacy avatar URLs, data URIs).
  - Computing the on-disk cache path.
  - Reading cached bytes (zero network).
  - Fetching from backend with the desktop auth token.
  - Best-effort background prefetch (used right after a popup notification
    is enqueued so the bytes are warm before the popup window renders).
  - LRU pruning on a configurable byte / file budget.

Used by both ``app.api.local_access_api_v2`` (the /image-cache HTTP handler
that the Tauri ``<img>`` element hits) and the live engines (ULTRA + AGENT)
who call ``prefetch()`` on the way to enqueuing a popup. Keeping the path
in one module is what makes the prefetch and the serve hit the same files.
"""
from __future__ import annotations

import hashlib
import logging
import mimetypes
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

from app.core.app_const import MONCLUB_BASE_URL
from app.core import telemetry as _tel

_logger = logging.getLogger(__name__)

# Match dashboard's legacy avatar URLs and rewrite to the new path. Mirrors
# the regex in app/api/local_access_api_v2.py — kept identical so the cached
# bytes hit the same file regardless of which side requested the URL.
_LEGACY_DASHBOARD_AVATAR_RE = re.compile(
    r"^/?assets/(?:avatars|images/avatar)/avatar-(\d+)\.(?:png|jpe?g|webp)$",
    re.IGNORECASE,
)

_VALID_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".ico", ".webp"}

# Max single image size we'll write to disk. Anything bigger is treated as
# a server-side bug — popups don't need 5MB+ photos and we don't want one
# bad row to evict the rest of the cache.
_MAX_IMAGE_BYTES = 5 * 1024 * 1024

# Default network timeout. Old code used 2s which routinely failed on slow
# Tunisian links — 8s is high enough for first fetch over flaky 4G but still
# bounded enough to surface a real outage to the popup as a quick fallback.
_DEFAULT_FETCH_TIMEOUT_SEC = 8.0

_pool_lock = threading.Lock()
_pool: Optional[ThreadPoolExecutor] = None
_inflight_lock = threading.Lock()
_inflight: Set[str] = set()


def _get_pool() -> ThreadPoolExecutor:
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = ThreadPoolExecutor(
                max_workers=4, thread_name_prefix="popup-img-prefetch"
            )
        return _pool


def cache_dir() -> str:
    """Resolve the on-disk cache directory under the Access data dir."""
    try:
        from access.storage import current_access_runtime_db_path
        db_path = str(current_access_runtime_db_path())
        base_dir = os.path.dirname(db_path) if db_path else os.getcwd()
    except Exception:
        base_dir = os.getcwd()
    path = os.path.join(base_dir, "cache", "images")
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        pass
    return path


def normalize_url(raw: str) -> str:
    """Return an absolute fetch URL (or empty / data-URI passthrough)."""
    s = (raw or "").strip()
    if not s:
        return ""
    m = _LEGACY_DASHBOARD_AVATAR_RE.match(s)
    if m:
        s = f"/assets/images/avatar/avatar-{m.group(1)}.webp"
    if s.startswith("data:"):
        return s
    if s.startswith("http://") or s.startswith("https://"):
        return s
    if s.startswith("//"):
        return f"https:{s}"
    if s.startswith("/"):
        return urljoin(MONCLUB_BASE_URL.rstrip("/") + "/", s.lstrip("/"))
    return urljoin(MONCLUB_BASE_URL.rstrip("/") + "/", s)


def cache_path(url: str) -> str:
    """Cache file path for a normalized URL. Always inside cache_dir()."""
    h = hashlib.sha1(url.encode("utf-8", errors="ignore")).hexdigest()
    ext = os.path.splitext(urlparse(url).path or "")[1].lower()
    if ext not in _VALID_EXTS:
        ext = ".png"
    return os.path.join(cache_dir(), f"{h}{ext}")


def guess_mime(path: str) -> str:
    m, _ = mimetypes.guess_type(path)
    return m or "image/png"


def etag_for(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8", errors="ignore")).hexdigest()


def _load_auth_token() -> str:
    try:
        from access.store import load_auth_token
        auth = load_auth_token()
        token = getattr(auth, "token", None) if auth else None
        return str(token).strip() if token else ""
    except Exception:
        return ""


def _atomic_write(target: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(target), exist_ok=True)
    tmp = target + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    try:
        os.replace(tmp, target)
    except OSError:
        os.rename(tmp, target)


def read_cached(url: str) -> Optional[Tuple[bytes, str]]:
    """Return (bytes, path) if cached and readable, else None."""
    if not url or url.startswith("data:"):
        return None
    target = cache_path(url)
    try:
        if os.path.isfile(target):
            with open(target, "rb") as f:
                return f.read(), target
    except OSError:
        return None
    return None


@_tel.timed("IMG_FETCH_DUR", slow_ms=0, warn_ms=3000)
def fetch_and_cache(
    url: str,
    *,
    timeout_sec: float = _DEFAULT_FETCH_TIMEOUT_SEC,
) -> Optional[Tuple[bytes, str]]:
    """Fetch a normalized URL from the backend and write to cache.

    Returns ``(bytes, target_path)`` on success, ``None`` on any failure.
    Never raises — popup path can't tolerate exceptions.
    """
    if not url or url.startswith("data:"):
        return None

    headers = {"User-Agent": "MonClubAccess/1.0", "Accept": "*/*"}
    token = _load_auth_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    target = cache_path(url)
    _t0 = time.monotonic()
    try:
        r = requests.get(url, headers=headers, timeout=timeout_sec)
        _dur = round((time.monotonic() - _t0) * 1000)
        if r.status_code < 200 or r.status_code >= 300:
            _logger.debug(
                "[popup-image] fetch failed url=%s status=%s", url, r.status_code
            )
            _tel.warn("IMG_FETCH_HTTP", status=r.status_code, dur_ms=_dur)
            return None
        data = r.content or b""
        if not data:
            _tel.warn("IMG_FETCH_EMPTY", dur_ms=_dur)
            return None
        if len(data) > _MAX_IMAGE_BYTES:
            _logger.warning(
                "[popup-image] image too large url=%s bytes=%d", url, len(data)
            )
            _tel.warn("IMG_FETCH_TOO_LARGE", bytes=len(data), dur_ms=_dur)
            return None
        try:
            _atomic_write(target, data)
        except OSError as exc:
            _logger.warning("[popup-image] write failed target=%s: %s", target, exc)
            _tel.warn("IMG_FETCH_WRITE_FAIL", bytes=len(data), dur_ms=_dur)
            return data, target
        _tel.event("IMG_FETCH_OK", bytes=len(data), dur_ms=_dur)
        return data, target
    except Exception as exc:
        # The slow/flaky-4G timeout path — the popup shows a placeholder here.
        _logger.debug("[popup-image] fetch error url=%s: %s", url, exc)
        _tel.warn(
            "IMG_FETCH_ERROR", err=type(exc).__name__,
            dur_ms=round((time.monotonic() - _t0) * 1000),
        )
        return None


@_tel.timed("IMG_PREFETCH_SUBMIT", slow_ms=20)
def prefetch(raw_url: str) -> None:
    """Best-effort background prefetch of a popup image.

    Idempotent — a second call for the same URL while the first is still in
    flight is a no-op. Already-cached files are skipped without touching disk
    beyond an ``os.path.isfile`` stat. Always returns immediately.
    """
    if not raw_url:
        return
    url = normalize_url(raw_url)
    if not url or url.startswith("data:"):
        return
    target = cache_path(url)
    try:
        if os.path.isfile(target):
            return
    except OSError:
        return

    with _inflight_lock:
        if url in _inflight:
            return
        _inflight.add(url)

    try:
        _get_pool().submit(_do_prefetch, url)
    except RuntimeError:
        # Pool was shut down (process exit). Drop the inflight marker so a
        # future re-init doesn't see a stale entry.
        with _inflight_lock:
            _inflight.discard(url)


def _do_prefetch(url: str) -> None:
    try:
        fetch_and_cache(url)
    finally:
        with _inflight_lock:
            _inflight.discard(url)


def prune(max_bytes: int, max_files: int) -> int:
    """Evict oldest (by mtime) entries until under both budgets.

    Returns the number of files removed. Safe to call from a background
    thread. Never raises.
    """
    if max_bytes <= 0 and max_files <= 0:
        return 0
    try:
        directory = cache_dir()
        entries = []
        total_bytes = 0
        for name in os.listdir(directory):
            full = os.path.join(directory, name)
            try:
                st = os.stat(full)
            except OSError:
                continue
            if not os.path.isfile(full):
                continue
            entries.append((st.st_mtime, st.st_size, full))
            total_bytes += st.st_size
    except OSError:
        return 0

    if not entries:
        return 0

    over_bytes = max_bytes > 0 and total_bytes > max_bytes
    over_files = max_files > 0 and len(entries) > max_files
    if not over_bytes and not over_files:
        return 0

    entries.sort()  # oldest first
    removed = 0
    i = 0
    while i < len(entries) and (
        (max_bytes > 0 and total_bytes > max_bytes)
        or (max_files > 0 and (len(entries) - i) > max_files)
    ):
        _mtime, size, path = entries[i]
        try:
            os.remove(path)
            total_bytes -= size
            removed += 1
        except OSError:
            pass
        i += 1
    if removed:
        _logger.info(
            "[popup-image] pruned %d entries (now ~%d bytes, %d files)",
            removed, total_bytes, len(entries) - removed,
        )
    return removed


_last_prune_at = 0.0
_PRUNE_MIN_INTERVAL_SEC = 60.0


def maybe_prune(max_bytes: int, max_files: int) -> None:
    """Throttled prune; safe to call from hot paths (no more than once/min)."""
    global _last_prune_at
    now = time.monotonic()
    if now - _last_prune_at < _PRUNE_MIN_INTERVAL_SEC:
        return
    _last_prune_at = now
    try:
        prune(max_bytes, max_files)
    except Exception:
        _logger.debug("[popup-image] prune failed", exc_info=True)


__all__ = [
    "cache_dir",
    "cache_path",
    "etag_for",
    "fetch_and_cache",
    "guess_mime",
    "maybe_prune",
    "normalize_url",
    "prefetch",
    "prune",
    "read_cached",
]

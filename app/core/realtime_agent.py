# app/core/realtime_agent.py
import hashlib
import json
import os
import queue
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional

from app.core.db import (
    insert_access_history,
    prune_access_history,
    list_sync_users,
    list_sync_gym_access_credentials,
    load_agent_rtlog_state,
    save_agent_rtlog_state,
    access_history_exists,
)
from access.storage import current_access_runtime_db_path
from app.core.utils import ensure_dirs
from app.sdk.pullsdk import PullSDKDevice
from app.core.access_types import AccessEvent, NotificationRequest, HistoryRecord
from app.core.access_verification import (
    verify_totp,
    verify_card,
    load_local_state,
)


# ===================== constants =====================

_RECONNECT_BACKOFF_BASE_SEC: float = 0.25
_RECONNECT_BACKOFF_MAX_SEC: float = 30.0


# ===================== generic helpers =====================

def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return default  # type: ignore[return-value]
        if isinstance(v, bool):
            return int(v)
        return int(float(str(v).strip()))
    except Exception:
        return default  # type: ignore[return-value]


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return default
        return float(str(v).strip())
    except Exception:
        return default


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    try:
        return str(v)
    except Exception:
        return default


def _sha1_obj(o: Any) -> str:
    try:
        s = json.dumps(o, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except Exception:
        s = _safe_str(o, "")
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()


def _now_ms() -> float:
    return time.perf_counter() * 1000.0


def _parse_event_time_to_epoch(s: str, tz_offset_sec: int = 0) -> Optional[float]:
    """
    Best-effort parsing of RTLog eventTime into epoch seconds.
    Supports:
      - unix seconds or milliseconds
      - ISO 8601 (with Z or offset)
      - 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DDTHH:MM:SS'
    """
    raw = (s or "").strip()
    if not raw:
        return None

    # numeric epoch (seconds/ms)
    if raw.isdigit():
        try:
            v = int(raw)
            if v > 10_000_000_000:  # ms
                return float(v) / 1000.0
            if v > 1_000_000_000:  # sec
                return float(v)
        except Exception:
            pass

    # ISO with Z
    try:
        iso = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        pass

    # common fallback formats
    # Device timestamps are local time, not UTC.
    # tz_offset_sec = device UTC offset in seconds (e.g., +10800 for UTC+3).
    # Subtracting gives approximate UTC epoch for cursor comparison.
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.timestamp() - tz_offset_sec
        except Exception:
            continue

    return None


def _boolish(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return int(v) != 0
    s = _safe_str(v, "").strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return default


def _clamp_int(v: Any, default: int, lo: int, hi: int) -> int:
    x = _safe_int(v, default)
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def _clamp_float(v: Any, default: float, lo: float, hi: float) -> float:
    x = _safe_float(v, default)
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


# ===================== Read backend-driven settings from SQLite cache =====================

from app.core.settings_reader import (
    get_backend_global_settings as _get_backend_global_settings,   # ✅ normalized-table source of truth
    normalize_device_settings as _normalize_device_settings,       # ✅ works with camelCase GymDeviceDto dicts
    normalize_access_data_mode as _normalize_access_data_mode,     # ✅ DEVICE/AGENT
)


# ===================== Image cache for notifications =====================

class ImageCache:
    def __init__(
        self,
        *,
        cache_dir: str,
        enabled: bool = True,
        timeout_sec: float = 2.0,
        max_bytes: int = 5 * 1024 * 1024,
        max_files: int = 1000,
        prune_every_n: int = 200,
    ):
        self.enabled = bool(enabled)
        self.timeout_sec = float(timeout_sec)
        self.max_bytes = int(max_bytes)
        self.max_files = int(max_files)
        self.prune_every_n = int(prune_every_n)

        self._lock = threading.Lock()
        self._memo: Dict[str, str] = {}
        self._hits = 0

        self.cache_dir = cache_dir
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except Exception:
            pass

    def _is_url(self, s: str) -> bool:
        try:
            p = urllib.parse.urlparse(s)
            return p.scheme in ("http", "https") and bool(p.netloc)
        except Exception:
            return False

    def _ext_from_url(self, url: str) -> str:
        try:
            p = urllib.parse.urlparse(url)
            base = os.path.basename(p.path or "")
            _, ext = os.path.splitext(base)
            ext = (ext or "").lower().strip()
            if ext in (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".ico", ".webp"):
                return ext
        except Exception:
            pass
        return ".png"

    def _target_path(self, url: str) -> str:
        h = hashlib.sha1(url.encode("utf-8", errors="ignore")).hexdigest()
        ext = self._ext_from_url(url)
        return os.path.join(self.cache_dir, f"{h}{ext}")

    def _download(self, url: str, target_path: str) -> bool:
        tmp = target_path + ".tmp"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "MonClubAccess/1.0", "Accept": "*/*"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                data = resp.read(self.max_bytes + 1)
                if not data:
                    return False
                if len(data) > self.max_bytes:
                    return False

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with open(tmp, "wb") as f:
                f.write(data)

            try:
                os.replace(tmp, target_path)
            except Exception:
                try:
                    os.remove(target_path)
                except Exception:
                    pass
                os.rename(tmp, target_path)

            return True
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
            return False

    def _maybe_prune(self) -> None:
        if self.max_files <= 0:
            return
        try:
            files = []
            for name in os.listdir(self.cache_dir):
                p = os.path.join(self.cache_dir, name)
                if os.path.isfile(p):
                    try:
                        st = os.stat(p)
                        files.append((st.st_mtime, p))
                    except Exception:
                        continue

            if len(files) <= self.max_files:
                return

            files.sort(key=lambda x: x[0])  # oldest first
            to_delete = len(files) - self.max_files
            for i in range(max(0, to_delete)):
                try:
                    os.remove(files[i][1])
                except Exception:
                    pass
        except Exception:
            return

    def resolve(self, url_or_path: str) -> str:
        s = (url_or_path or "").strip()
        if not s:
            return ""
        if not self.enabled:
            return ""

        try:
            if os.path.exists(s) and os.path.isfile(s):
                return s
        except Exception:
            pass

        if not self._is_url(s):
            return ""

        with self._lock:
            if s in self._memo:
                p = self._memo[s]
                try:
                    if os.path.exists(p) and os.path.isfile(p):
                        return p
                except Exception:
                    self._memo.pop(s, None)

            target = self._target_path(s)
            try:
                if os.path.exists(target) and os.path.isfile(target):
                    self._memo[s] = target
                    return target
            except Exception:
                pass

        ok = self._download(s, target)

        with self._lock:
            if ok:
                self._memo[s] = target
            self._hits += 1
            if self.prune_every_n > 0 and (self._hits % self.prune_every_n == 0):
                self._maybe_prune()

        return target if ok else ""

    def get_cached(self, url_or_path: str) -> str:
        """
        F-024: Non-blocking cache check. Returns cached path if available, otherwise "" (no download).
        Use this to avoid blocking the notification thread on image download.
        """
        s = (url_or_path or "").strip()
        if not s:
            return ""
        if not self.enabled:
            return ""

        try:
            if os.path.exists(s) and os.path.isfile(s):
                return s
        except Exception:
            pass

        if not self._is_url(s):
            return ""

        with self._lock:
            if s in self._memo:
                p = self._memo[s]
                try:
                    if os.path.exists(p) and os.path.isfile(p):
                        return p
                except Exception:
                    self._memo.pop(s, None)

            target = self._target_path(s)
            try:
                if os.path.exists(target) and os.path.isfile(target):
                    self._memo[s] = target
                    return target
            except Exception:
                pass

        return ""


# ===================== dataclasses =====================

@dataclass
class CommandResult:
    ok: bool
    error: str
    cmd_ms: float


def _popup_payload_from_request(req: NotificationRequest) -> Dict[str, Any]:
    return {
        "eventId": req.event_id,
        "title": req.title,
        "message": req.message,
        "imagePath": req.image_path,
        "popupShowImage": req.popup_show_image,
        "userFullName": req.user_full_name,
        "userImage": req.user_image,
        "userValidFrom": req.user_valid_from,
        "userValidTo": req.user_valid_to,
        "userMembershipId": req.user_membership_id,
        "userPhone": req.user_phone,
        "deviceId": req.device_id,
        "deviceName": req.device_name,
        "allowed": req.allowed,
        "reason": req.reason,
        "scanMode": req.scan_mode,
        "popupDurationSec": req.popup_duration_sec,
        "popupEnabled": req.popup_enabled,
        "winNotifyEnabled": req.win_notify_enabled,
        "userBirthday": req.user_birthday,
        "imageSource": req.image_source,
        "userImageStatus": req.user_image_status,
    }


@dataclass
class DeviceStatus:
    device_id: int
    name: str
    enabled: bool
    connected: bool
    last_error: str = ""
    last_event_at: float = 0.0
    last_poll_ms: float = 0.0
    polls: int = 0
    events: int = 0
    reconnects: int = 0
    poll_ema: float = 0.0
    cmd_ema: float = 0.0
    dropped_events: int = 0


# ===================== EMA =====================

class EMA:
    def __init__(self, alpha: float = 0.2):
        self.alpha = float(alpha)
        self.value = 0.0
        self.ready = False

    def add(self, x: float) -> None:
        x = float(x)
        if not self.ready:
            self.value = x
            self.ready = True
            return
        self.value = (self.alpha * x) + ((1.0 - self.alpha) * self.value)


# ===================== Notification Gate (rate limit + dedupe) =====================

class NotificationGate:
    def __init__(self, *, global_settings: Callable[[], Dict[str, Any]]):
        self.global_settings = global_settings
        self._lock = threading.Lock()
        self._times: Deque[float] = deque(maxlen=2000)  # timestamps (sec)
        self._recent: Dict[str, float] = {}  # key -> last_time

    def allow(self, *, key: str) -> bool:
        """
        key should represent "same notification" for dedupe (ex: sha1 of message).
        """
        now = time.time()
        g = self.global_settings() or {}
        rate = _safe_int(g.get("notification_rate_limit_per_minute"), 30)
        dedupe = _safe_int(g.get("notification_dedupe_window_sec"), 30)

        if rate < 0:
            rate = 0
        if dedupe < 0:
            dedupe = 0

        with self._lock:
            # 1) dedupe check (read-only — do not update stamp yet)
            if dedupe > 0:
                last = self._recent.get(key)
                if last is not None and (now - float(last)) < float(dedupe):
                    return False

                # prune old recent entries opportunistically
                if len(self._recent) > 5000:
                    cut = now - float(dedupe) - 5.0
                    for k, t in list(self._recent.items())[:2000]:
                        if t < cut:
                            self._recent.pop(k, None)

            # 2) rate limit check
            if rate == 0:
                return False

            cutoff = now - 60.0
            while self._times and self._times[0] < cutoff:
                self._times.popleft()

            if len(self._times) >= rate:
                return False

            # 3) Both checks passed — commit the stamp and count
            if dedupe > 0:
                self._recent[key] = now
            self._times.append(now)
            return True


# ===================== Command bus =====================

class DeviceCommandBus:
    def __init__(self, *, workers_provider: Callable[[int], "DeviceWorker"]):
        self._workers_provider = workers_provider

    def open_door(self, *, device_id: int, door_id: int, pulse_time_ms: int, timeout_ms: int = 4000) -> CommandResult:
        w = self._workers_provider(int(device_id))
        if not w:
            return CommandResult(ok=False, error="worker not found or device disabled", cmd_ms=0.0)
        try:
            return w.open_door(door_id=int(door_id), pulse_time_ms=int(pulse_time_ms), timeout_ms=int(timeout_ms))
        except Exception as e:
            return CommandResult(ok=False, error=str(e), cmd_ms=0.0)


# ===================== Device worker (poll rtlog) =====================

class DeviceWorker(threading.Thread):
    def __init__(
        self,
        *,
        device_payload: Dict[str, Any],
        logger,
        event_queue: "queue.Queue[AccessEvent]",
        status_cb: Callable[[DeviceStatus], None],
        settings_provider: Callable[[int], Dict[str, Any]],
    ):
        super().__init__(daemon=True)
        self.logger = logger
        self.event_queue = event_queue
        self.status_cb = status_cb
        self.settings_provider = settings_provider

        self.device_payload = device_payload
        self.device_id = _safe_int(device_payload.get("id"), 0)
        self.device_name = _safe_str(device_payload.get("name"), f"device-{self.device_id}")

        self.stop_event = threading.Event()
        self.wake_event = threading.Event()

        self._device = PullSDKDevice(self.device_payload, logger=self.logger)

        # F-009: device timezone offset for local-time -> UTC epoch conversion
        self._device_tz_offset_sec: int = _safe_int(
            self.device_payload.get("timezoneOffsetSeconds") or
            self.device_payload.get("timezone_offset_seconds"),
            0,
        )

        # replay protection (in-memory LRU) + persisted cursor (db)
        self._seen: Deque[str] = deque(maxlen=10000)  # F-018: increased from 2000 to reduce eviction under burst

        self._last_event_at_str = ""
        self._last_event_id = ""
        self._last_event_epoch: Optional[float] = None
        self._state_dirty = False
        self._last_state_flush_s = 0.0

        try:
            st = load_agent_rtlog_state(self.device_id)
            if st:
                self._last_event_at_str = _safe_str(st.last_event_at, "")
                self._last_event_id = _safe_str(st.last_event_id, "")
                self._last_event_epoch = _parse_event_time_to_epoch(
                    self._last_event_at_str, tz_offset_sec=self._device_tz_offset_sec
                )
                if self._last_event_id:
                    self._seen.append(self._last_event_id)
                # F-016: Pre-populate seen deque with recent event IDs to prevent replay after restart
                try:
                    from app.core.db import get_recent_access_history
                    recent_rows = get_recent_access_history(limit=200)
                    for row in recent_rows:
                        eid = _safe_str(getattr(row, "event_id", ""), "")
                        if eid and eid not in self._seen:
                            self._seen.append(eid)
                except Exception:
                    pass
        except Exception:
            pass

        self._polls = 0
        self._events = 0
        self._reconnects = 0
        self._dropped_events = 0
        self._events_since_flush = 0

        # EMA tracking for performance
        self._poll_ema = EMA(alpha=0.2)
        self._cmd_ema = EMA(alpha=0.2)

        # Adaptive empty sleep
        self._empty_sleep_ms = 0.0

    def stop(self) -> None:
        self.stop_event.set()
        self.wake_event.set()

    def _emit_status(
        self,
        *,
        enabled: bool,
        connected: bool,
        last_error: str = "",
        last_event_at: float = 0.0,
        last_poll_ms: float = 0.0,
    ) -> None:
        st = DeviceStatus(
            device_id=self.device_id,
            name=self.device_name,
            enabled=bool(enabled),
            connected=bool(connected),
            last_error=_safe_str(last_error),
            last_event_at=float(last_event_at),
            last_poll_ms=float(last_poll_ms),
            polls=int(self._polls),
            events=int(self._events),
            reconnects=int(self._reconnects),
            poll_ema=float(self._poll_ema.value if self._poll_ema.ready else 0.0),
            cmd_ema=float(self._cmd_ema.value if self._cmd_ema.ready else 0.0),
            dropped_events=int(self._dropped_events),
        )
        try:
            self.status_cb(st)
        except Exception:
            pass

    def _replay_seen(self, event_id: str) -> bool:
        if not event_id:
            return False
        if event_id in self._seen:
            return True
        self._seen.append(event_id)
        return False

    def _is_old_by_cursor(self, *, event_id: str, event_time_str: str) -> bool:
        if self._last_event_id and event_id == self._last_event_id:
            return True

        epoch = _parse_event_time_to_epoch(event_time_str, tz_offset_sec=self._device_tz_offset_sec)
        if epoch is None or self._last_event_epoch is None:
            return False

        if epoch < self._last_event_epoch:
            return True

        return False

    def _maybe_flush_state(self, force: bool = False) -> None:
        if not self._state_dirty:
            return
        now_s = time.time()
        if not force and (now_s - self._last_state_flush_s) < 1.0:
            return
        self._last_state_flush_s = now_s
        try:
            save_agent_rtlog_state(
                device_id=self.device_id,
                last_event_at=self._last_event_at_str,
                last_event_id=self._last_event_id,
            )
            self._state_dirty = False
        except Exception:
            pass

    def open_door(self, *, door_id: int, pulse_time_ms: int, timeout_ms: int = 4000) -> CommandResult:
        t0 = _now_ms()
        try:
            ok = self._device.open_door(
                door_id=int(door_id),
                pulse_time_ms=int(pulse_time_ms),
                timeout_ms=int(timeout_ms),
            )
            cmd_ms = _now_ms() - t0
            self._cmd_ema.add(cmd_ms)
            return CommandResult(ok=bool(ok), error="" if ok else "open_door failed", cmd_ms=cmd_ms)
        except Exception as e:
            cmd_ms = _now_ms() - t0
            self._cmd_ema.add(cmd_ms)
            return CommandResult(ok=False, error=str(e), cmd_ms=cmd_ms)

    def run(self) -> None:
        reconnect_attempt = 0
        last_error = ""

        while not self.stop_event.is_set():
            settings = self.settings_provider(self.device_id)

            enabled = bool(settings.get("enabled", True))
            if not enabled:
                try:
                    self._device.disconnect()
                except Exception:
                    pass
                self._emit_status(enabled=False, connected=False, last_error="disabled")
                self.wake_event.wait(timeout=0.5)
                self.wake_event.clear()
                continue

            # keep EMA alpha adjustable (future fields)
            try:
                self._poll_ema.alpha = float(settings.get("poll_ema_alpha", 0.2))
                self._cmd_ema.alpha = float(settings.get("cmd_ema_alpha", 0.2))
            except Exception:
                pass

            if not self._device.is_connected:
                ok = False
                try:
                    ok = self._device.ensure_connected()
                except Exception as _conn_exc:
                    ok = False
                    self.logger.warning(
                        "[RT][device=%s] ensure_connected raised: %s",
                        self.device_id, _conn_exc,
                    )

                if not ok:
                    reconnect_attempt += 1
                    self._reconnects += 1
                    last_error = "connect failed"
                    self._emit_status(enabled=True, connected=False, last_error=last_error)

                    backoff = min(_RECONNECT_BACKOFF_MAX_SEC, _RECONNECT_BACKOFF_BASE_SEC * (2 ** reconnect_attempt))
                    self.logger.warning(
                        "[RT][device=%s] connect FAILED (attempt=%d, reconnects=%d) — backoff=%.2fs",
                        self.device_id, reconnect_attempt, self._reconnects, backoff,
                    )
                    time.sleep(backoff)
                    continue

                reconnect_attempt = 0
                last_error = ""
                self.logger.info(
                    "[RT][device=%s] connected OK (name=%r, reconnects_total=%d)",
                    self.device_id, self.device_name, self._reconnects,
                )
                self._emit_status(enabled=True, connected=True, last_error="")

            poll_t0 = _now_ms()
            try:
                # F-021: Watchdog for blocking SDK calls — join with timeout to detect hangs
                _poll_timeout_sec = 15.0
                _result_holder: list = []
                _exc_holder: list = []

                def _poll_fn():
                    try:
                        _result_holder.append(self._device.poll_rtlog_once())
                    except Exception as _e:
                        _exc_holder.append(_e)

                _poll_thread = threading.Thread(target=_poll_fn, daemon=True)
                _poll_thread.start()
                _poll_thread.join(timeout=_poll_timeout_sec)

                if _poll_thread.is_alive():
                    self.logger.warning(
                        f"[RT][device={self.device_id}] poll_rtlog_once blocked >{_poll_timeout_sec}s — forcing reconnect"
                    )
                    try:
                        self._device.disconnect()
                    except Exception:
                        pass
                    raise RuntimeError(f"poll_rtlog_once watchdog timeout after {_poll_timeout_sec}s")

                if _exc_holder:
                    raise _exc_holder[0]

                rows = _result_holder[0] if _result_holder else []
                poll_ms = _now_ms() - poll_t0
                self._polls += 1
                self._poll_ema.add(poll_ms)

                # adaptive sleep knobs
                adaptive_sleep = bool(settings.get("adaptive_sleep", True))
                busy_min = float(_safe_int(settings.get("busy_sleep_min_ms"), 0))
                busy_max = float(_safe_int(settings.get("busy_sleep_max_ms"), 20))
                if busy_max < busy_min:
                    busy_max = busy_min

                empty_min = float(_safe_int(settings.get("empty_sleep_min_ms"), 50))
                empty_max = float(_safe_int(settings.get("empty_sleep_max_ms"), 100))
                if empty_max < empty_min:
                    empty_max = empty_min

                empty_factor = float(_safe_float(settings.get("empty_backoff_factor"), 1.35))
                if empty_factor < 1.0:
                    empty_factor = 1.0
                if empty_factor > 3.0:
                    empty_factor = 3.0

                empty_backoff_max = float(_safe_int(settings.get("empty_backoff_max_ms"), 200))
                if empty_backoff_max < 0:
                    empty_backoff_max = 0.0

                if not rows:
                    # no events => grow empty sleep
                    if not adaptive_sleep:
                        sleep_ms = max(50.0, empty_min)
                        self._empty_sleep_ms = sleep_ms
                    else:
                        if self._empty_sleep_ms <= 0.0:
                            self._empty_sleep_ms = max(0.0, empty_min)
                        else:
                            self._empty_sleep_ms = self._empty_sleep_ms * empty_factor

                        # ensure at least empty_min, and allow it to grow beyond empty_max up to empty_backoff_max
                        if self._empty_sleep_ms < empty_min:
                            self._empty_sleep_ms = empty_min
                        if self._empty_sleep_ms < empty_max:
                            # keep within base range initially
                            pass
                        if empty_backoff_max > 0:
                            self._empty_sleep_ms = min(self._empty_sleep_ms, empty_backoff_max)

                    self._emit_status(enabled=True, connected=True, last_error=last_error, last_poll_ms=poll_ms)
                    self._maybe_flush_state()

                    timeout_s = max(0.05, float(self._empty_sleep_ms) / 1000.0)
                    self.wake_event.wait(timeout=timeout_s)
                    self.wake_event.clear()
                    continue

                # rows exist => reset empty sleep
                self._empty_sleep_ms = 0.0

                for r in rows:
                    try:
                        event_id = _safe_str(r.get("eventId"), "") or _sha1_obj(r)
                        if not event_id:
                            continue

                        # F-028: access_history_exists check moved to DecisionService to reduce
                        # SQLite read contention in the hot polling path. _replay_seen handles
                        # in-session deduplication; cross-restart deduplication is handled by
                        # DecisionService and the access_history UNIQUE constraint.
                        if self._replay_seen(event_id):
                            continue

                        event_time_str = _safe_str(r.get("eventTime"), "")
                        if self._is_old_by_cursor(event_id=event_id, event_time_str=event_time_str):
                            continue

                        ev = AccessEvent(
                            event_id=event_id,
                            device_id=self.device_id,
                            door_id=_safe_int(r.get("doorId"), 0) if r.get("doorId") is not None else None,
                            event_type=_safe_str(r.get("eventType"), "RTLOG"),
                            card_no=_safe_str(r.get("cardNo"), ""),
                            event_time=event_time_str,
                            raw=r if isinstance(r, dict) else {"raw": _safe_str(r)},
                            poll_ms=float(poll_ms),
                            queued_at=_now_ms(),
                        )

                        self.logger.debug(
                            "[RT][device=%s] dispatching event: id=%s card=%r type=%s time=%s",
                            self.device_id, event_id,
                            ev.card_no, ev.event_type, ev.event_time,
                        )
                        try:
                            self.event_queue.put(ev, timeout=0.05)
                        except queue.Full:
                            self._dropped_events += 1
                            if self._dropped_events == 1 or self._dropped_events % 100 == 0:
                                self.logger.warning(
                                    f"[RT][device={self.device_id}] Event queue full — "
                                    f"dropping event {event_id} (total_dropped={self._dropped_events})"
                                )
                        except Exception:
                            pass

                        self._last_event_id = event_id
                        self._last_event_at_str = event_time_str or self._last_event_at_str
                        ep = _parse_event_time_to_epoch(event_time_str, tz_offset_sec=self._device_tz_offset_sec)
                        if ep is not None:
                            self._last_event_epoch = ep
                        self._state_dirty = True
                        self._events_since_flush += 1
                        if self._events_since_flush >= 10:
                            self._maybe_flush_state(force=True)
                            self._events_since_flush = 0

                        self._events += 1
                        self._emit_status(
                            enabled=True,
                            connected=True,
                            last_error=last_error,
                            last_event_at=time.time(),
                            last_poll_ms=poll_ms,
                        )
                    except Exception:
                        continue

                self._maybe_flush_state()

                # optional busy sleep to avoid tight looping
                if adaptive_sleep and (busy_min > 0 or busy_max > 0):
                    # Sleep between busy_min and busy_max ms, using poll latency as reference.
                    sleep_ms = max(float(busy_min), min(float(busy_max), float(poll_ms)))
                    if sleep_ms > 0:
                        self.wake_event.wait(timeout=max(0.0, sleep_ms / 1000.0))
                        self.wake_event.clear()

            except Exception as e:
                last_error = str(e)
                self._emit_status(enabled=True, connected=False, last_error=last_error)
                try:
                    self._device.disconnect()
                except Exception:
                    pass
                time.sleep(0.25)

        try:
            self._maybe_flush_state()
        except Exception:
            pass

        try:
            self._device.disconnect()
        except Exception:
            pass

        self._emit_status(enabled=False, connected=False, last_error="stopped")


# ===================== Decision service =====================

class DecisionService(threading.Thread):
    def __init__(
        self,
        *,
        logger,
        event_queue: "queue.Queue[AccessEvent]",
        command_bus: DeviceCommandBus,
        notify_q: "queue.Queue[NotificationRequest]",
        popup_q: "queue.Queue[NotificationRequest]",
        history_q: "queue.Queue[HistoryRecord]",
        settings_provider: Callable[[int], Dict[str, Any]],
        global_settings: Callable[[], Dict[str, Any]],
        notify_gate: NotificationGate,
        decision_ema: EMA,
        device_name_provider: Optional[Callable[[int], str]] = None,
    ):
        super().__init__(daemon=True)
        self.logger = logger
        self.event_queue = event_queue
        self.command_bus = command_bus
        self.notify_q = notify_q
        self.popup_q = popup_q
        self.history_q = history_q
        self.settings_provider = settings_provider
        self.global_settings = global_settings
        self.notify_gate = notify_gate
        self.decision_ema = decision_ema
        self.device_name_provider = device_name_provider or (lambda did: f"device-{did}")

        self._cache_lock = threading.Lock()
        # L-005: Cache TTL now configurable from backend settings (default 30s)
        # Increased from 2s to 30s: load_sync_cache() with 1000+ users was adding
        # 200-500ms to every decision that expired the 2s window.
        _g_settings = global_settings() if global_settings else {}
        self._cache_ttl_sec = float(_g_settings.get("decision_cache_ttl_sec", 30.0))

        self._creds_cache_at = 0.0
        self._creds_cache: List[Dict[str, Any]] = []

        self._users_cache_at = 0.0
        self._users_by_active_membership_id: Dict[int, Dict[str, Any]] = {}
        self._users_by_card: Dict[str, List[Dict[str, Any]]] = {}

        self.stop_event = threading.Event()

    def stop(self) -> None:
        self.stop_event.set()

    def _load_local_state(
        self,
    ) -> tuple[List[Dict[str, Any]], Dict[int, Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
        ttl = float(getattr(self, "_cache_ttl_sec", 2.0))
        if ttl < 0.5:
            ttl = 0.5  # F-012: minimum 0.5s to prevent DB read storms at TTL=0
        now_s = time.time()

        with self._cache_lock:
            need_creds = ttl <= 0 or (now_s - float(self._creds_cache_at)) > ttl
            need_users = ttl <= 0 or (now_s - float(self._users_cache_at)) > ttl

            if need_creds or need_users:
                creds, idx_by_am, idx_by_card = load_local_state()
                if need_creds:
                    self._creds_cache = creds
                    self._creds_cache_at = now_s
                if need_users:
                    self._users_by_active_membership_id = idx_by_am
                    self._users_by_card = idx_by_card
                    self._users_cache_at = now_s

            return list(self._creds_cache), dict(self._users_by_active_membership_id), dict(self._users_by_card)

    def _verify_card(self, *, scanned: str, settings: Dict[str, Any], users_by_card: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        return verify_card(scanned=scanned, settings=settings, users_by_card=users_by_card)

    def _verify_totp(self, *, scanned: str, settings: Dict[str, Any], creds_payload: List[Dict[str, Any]], users_by_am: Dict[int, Dict[str, Any]], users_by_card: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        return verify_totp(scanned=scanned, settings=settings, creds_payload=creds_payload, users_by_am=users_by_am, users_by_card=users_by_card)

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                ev = self.event_queue.get(timeout=0.05)
            except queue.Empty:
                continue

            # F-028: Check history deduplication here (single thread) rather than in DeviceWorker
            # (one per device) to reduce SQLite read contention under burst conditions.
            if access_history_exists(ev.event_id):
                continue

            settings = self.settings_provider(ev.device_id)
            queue_ms = _now_ms() - ev.queued_at if ev.queued_at > 0 else 0.0
            t0 = _now_ms()

            t_load = _now_ms()
            creds_payload, users_by_am, users_by_card = self._load_local_state()
            load_ms = _now_ms() - t_load

            t_verify = _now_ms()
            vr = self._verify_totp(
                scanned=ev.card_no,
                settings=settings,
                creds_payload=creds_payload,
                users_by_am=users_by_am,
                users_by_card=users_by_card,
            )
            verify_ms = _now_ms() - t_verify

            allowed = bool(vr.get("allowed", False))
            reason = _safe_str(vr.get("reason", "DENY"))
            scan_mode = _safe_str(vr.get("scanMode", ""), "")

            action = "OPEN_DOOR" if allowed else "NONE"
            door_id = ev.door_id if ev.door_id is not None else _safe_int(settings.get("door_entry_id"), 1)
            pulse_time_ms = _safe_int(settings.get("pulse_time_ms"), 3000)

            decision_ms = _now_ms() - t0
            self.decision_ema.add(decision_ms)

            self.logger.info(
                "[RT][device=%s] DECISION: card=%r allowed=%s reason=%s scan_mode=%s "
                "door_id=%s | pollMs=%.1f queueMs=%.1f loadMs=%.1f verifyMs=%.1f decisionMs=%.1f | event_id=%s",
                ev.device_id, ev.card_no, allowed, reason, scan_mode,
                door_id, ev.poll_ms, queue_ms, load_ms, verify_ms, decision_ms, ev.event_id,
            )

            # F-013: INSERT OR IGNORE into access_history BEFORE opening door.
            # rowcount==1 means this worker claimed the event; rowcount==0 means another worker already inserted it.
            # This prevents TOCTOU double door-open: the INSERT is atomic on the UNIQUE(event_id) constraint.
            _history_claimed = 0
            if bool(settings.get("save_history", True)):
                try:
                    _history_claimed = insert_access_history(
                        event_id=ev.event_id,
                        device_id=ev.device_id,
                        door_id=int(door_id) if door_id is not None else None,
                        card_no=ev.card_no,
                        event_time=ev.event_time,
                        event_type=ev.event_type,
                        allowed=allowed,
                        reason=reason,
                        poll_ms=float(ev.poll_ms),
                        decision_ms=float(decision_ms),
                        cmd_ms=0.0,
                        cmd_ok=None,
                        cmd_error=None,
                        raw=dict(ev.raw),
                    )
                except Exception as ex:
                    _history_claimed = 0
                    self.logger.exception(
                        "[RT][device=%s] access_history insert failed for event_id=%s; denying door-open: %s",
                        ev.device_id,
                        ev.event_id,
                        ex,
                    )

            cmd_res = CommandResult(ok=True, error="", cmd_ms=0.0)
            if action == "OPEN_DOOR":
                # F-013: only open door if we claimed the event (rowcount>0); skip if another worker already processed it
                if _history_claimed > 0 or not bool(settings.get("save_history", True)):
                    cmd_timeout_ms = _safe_int(settings.get("cmd_timeout_ms"), 4000)
                    self.logger.info(
                        "[RT][device=%s] OPEN_DOOR: door_id=%s pulse_ms=%s event_id=%s",
                        ev.device_id, door_id, pulse_time_ms, ev.event_id,
                    )
                    cmd_res = self.command_bus.open_door(
                        device_id=ev.device_id,
                        door_id=int(door_id),
                        pulse_time_ms=int(pulse_time_ms),
                        timeout_ms=int(cmd_timeout_ms),
                    )
                    if cmd_res.ok:
                        self.logger.info(
                            "[RT][device=%s] OPEN_DOOR OK: door_id=%s cmd_ms=%.1f event_id=%s",
                            ev.device_id, door_id, cmd_res.cmd_ms, ev.event_id,
                        )
                    else:
                        self.logger.error(
                            "[RT][device=%s] OPEN_DOOR FAILED: door_id=%s error=%r cmd_ms=%.1f event_id=%s",
                            ev.device_id, door_id, cmd_res.error, cmd_res.cmd_ms, ev.event_id,
                        )
                else:
                    # Already processed by another worker — skip notification too
                    self.logger.debug(
                        "[RT][device=%s] OPEN_DOOR skipped (duplicate event_id=%s history_claimed=%s)",
                        ev.device_id, ev.event_id, _history_claimed,
                    )
                    continue

            # Per-device notifications (backend controlled)
            if not bool(settings.get("show_notifications", True)):
                continue

            user = vr.get("user") if isinstance(vr, dict) else None
            user_name = _safe_str((user or {}).get("fullName"), "-") if isinstance(user, dict) else "-"
            user_phone = _safe_str((user or {}).get("phone"), "") if isinstance(user, dict) else ""
            user_id = _safe_str((user or {}).get("userId"), "") if isinstance(user, dict) else ""
            user_image = _safe_str((user or {}).get("image"), "") if isinstance(user, dict) else ""
            am_id = vr.get("activeMembershipId")
            age = vr.get("ageSeconds")
            took = vr.get("tookMs")

            title = f"Access {'OK' if allowed and cmd_res.ok else 'DENY'}"

            if allowed:
                msg = f"{user_name}"
                if user_phone:
                    msg += f" | phone={user_phone}"
                if user_id:
                    msg += f" | userId={user_id}"
                if am_id not in (None, "", 0):
                    msg += f" | amId={am_id}"
                msg += f" | deviceId={ev.device_id} door={door_id}"
                if scan_mode:
                    msg += f" | mode={scan_mode}"
                if age is not None:
                    msg += f" | age={age}s"
                if took is not None:
                    try:
                        msg += f" | checkMs={float(took):.1f}"
                    except Exception:
                        msg += f" | checkMs={took}"
                try:
                    msg += f" | pollMs={float(ev.poll_ms):.1f} decisionMs={float(decision_ms):.1f} cmdMs={float(cmd_res.cmd_ms):.1f}"
                except Exception:
                    pass
            else:
                msg = f"reason={reason} | deviceId={ev.device_id} door={door_id} | code={ev.card_no or '-'}"
                if scan_mode:
                    msg += f" | mode={scan_mode}"
                took2 = vr.get("tookMs")
                if took2 is not None:
                    try:
                        msg += f" | checkMs={float(took2):.1f}"
                    except Exception:
                        msg += f" | checkMs={took2}"
                try:
                    msg += f" | pollMs={float(ev.poll_ms):.1f} decisionMs={float(decision_ms):.1f} cmdMs={float(cmd_res.cmd_ms):.1f}"
                except Exception:
                    pass

            if not cmd_res.ok and cmd_res.error:
                msg += f" | cmdError={cmd_res.error}"

            # global dedupe/rate limit (backend controlled, gym-scoped)
            dedupe_key = hashlib.sha1((title + "|" + msg).encode("utf-8", errors="ignore")).hexdigest()
            if not self.notify_gate.allow(key=dedupe_key):
                continue

            req = NotificationRequest(
                event_id=ev.event_id,
                title=title,
                message=msg,
                image_path=user_image if allowed else "",
                popup_show_image=bool(settings.get("popup_show_image", True)),
                # enriched fields for Tauri popup
                user_full_name=user_name,
                user_image=user_image,
                user_valid_from=_safe_str((user or {}).get("validFrom", (user or {}).get("valid_from")), "") if isinstance(user, dict) else "",
                user_valid_to=_safe_str((user or {}).get("validTo", (user or {}).get("valid_to")), "") if isinstance(user, dict) else "",
                user_membership_id=_safe_int(am_id, 0) if am_id else None,
                user_birthday=_safe_str((user or {}).get("birthday"), "") if isinstance(user, dict) else "",
                user_phone=user_phone,
                device_id=int(ev.device_id),
                device_name=self.device_name_provider(int(ev.device_id)),
                allowed=bool(allowed and cmd_res.ok),
                reason=reason,
                scan_mode=scan_mode or "",
                popup_duration_sec=_safe_int(settings.get("popup_duration_sec"), 3),
                popup_enabled=bool(settings.get("popup_enabled", True)),
                win_notify_enabled=bool(settings.get("win_notify_enabled", True)),
            )

            # Windows notification (per-device winNotifyEnabled)
            if bool(settings.get("win_notify_enabled", True)):
                try:
                    self.notify_q.put(req, timeout=0.05)
                    self.logger.debug(
                        "[RT][device=%s] win_notify enqueued: allowed=%s user=%r event_id=%s",
                        ev.device_id, req.allowed, req.user_full_name, req.event_id,
                    )
                except queue.Full:
                    self.logger.warning(
                        "[RT][device=%s] win_notify queue FULL — dropping event_id=%s",
                        ev.device_id, ev.event_id,
                    )
                except Exception as _nq_ex:
                    self.logger.warning("[RT][device=%s] win_notify enqueue error: %s", ev.device_id, _nq_ex)

            # Popup (Tkinter) (per-device popupEnabled)
            if bool(settings.get("popup_enabled", True)):
                try:
                    self.popup_q.put(req, timeout=0.05)
                    self.logger.debug(
                        "[RT][device=%s] popup enqueued: allowed=%s user=%r event_id=%s",
                        ev.device_id, req.allowed, req.user_full_name, req.event_id,
                    )
                except queue.Full:
                    self.logger.warning(
                        "[RT][device=%s] popup queue FULL — dropping event_id=%s",
                        ev.device_id, ev.event_id,
                    )
                except Exception as _pq_ex:
                    self.logger.warning("[RT][device=%s] popup enqueue error: %s", ev.device_id, _pq_ex)


# ===================== Notification service (Windows) =====================

class NotificationService(threading.Thread):
    def __init__(self, *, logger, notify_q: "queue.Queue[NotificationRequest]", global_settings: Callable[[], Dict[str, Any]]):
        super().__init__(daemon=True)
        self.logger = logger
        self.notify_q = notify_q
        self.global_settings = global_settings
        self.stop_event = threading.Event()
        self._is_alive = False

        try:
            ensure_dirs()
        except Exception:
            pass
        access_db_path = str(current_access_runtime_db_path())
        base_dir = os.path.dirname(access_db_path) if access_db_path else os.getcwd()
        cache_dir = os.path.join(base_dir, "cache", "images")

        # create cache with defaults; runtime will update .enabled/.timeout/.limits from backend settings
        self._img_cache = ImageCache(cache_dir=cache_dir)
        # L-002: Use bounded thread pool for background image downloads instead of spawning unbounded threads
        from concurrent.futures import ThreadPoolExecutor
        self._img_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="img-dl")

    def stop(self) -> None:
        self.stop_event.set()

    def is_alive_ok(self) -> bool:
        return bool(self._is_alive)

    def run(self) -> None:
        try:
            from winotify import Notification, audio  # type: ignore
        except Exception:
            Notification = None
            audio = None

        self._is_alive = True

        while not self.stop_event.is_set():
            try:
                r = self.notify_q.get(timeout=0.25)
            except queue.Empty:
                continue

            try:
                g = self.global_settings() or {}
                if not bool(g.get("notification_service_enabled", True)):
                    continue

                if not Notification:
                    continue

                # apply backend cache knobs dynamically
                try:
                    self._img_cache.enabled = bool(g.get("image_cache_enabled", True))
                    self._img_cache.timeout_sec = float(g.get("image_cache_timeout_sec", 2.0))
                    self._img_cache.max_bytes = int(g.get("image_cache_max_bytes", 5 * 1024 * 1024))
                    self._img_cache.max_files = int(g.get("image_cache_max_files", 1000))
                except Exception:
                    pass

                icon_path = ""
                if r.image_path:
                    # F-024: Try to get from cache without downloading (non-blocking)
                    icon_path = self._img_cache.get_cached(r.image_path)
                    if not icon_path:
                        # Not in cache — show notification without image, download in background
                        def _bg_download(url):
                            try:
                                self._img_cache.resolve(url)
                            except Exception:
                                pass
                        # L-002: Submit to bounded thread pool instead of spawning unbounded threads
                        self._img_executor.submit(_bg_download, r.image_path)

                # respect per-device popupShowImage only for popups; Windows toast can still show icon
                n = Notification(app_id="MonClub Access", title=r.title, msg=r.message, icon=icon_path or "")
                try:
                    if audio:
                        n.set_audio(audio.Default, loop=False)
                except Exception:
                    pass
                n.show()
            except Exception as e:
                self.logger.debug(f"[RT][notify failed] {e}")


# ===================== History service =====================

class HistoryService(threading.Thread):
    def __init__(self, *, logger, history_q: "queue.Queue[HistoryRecord]", global_settings: Callable[[], Dict[str, Any]]):
        super().__init__(daemon=True)
        self.logger = logger
        self.history_q = history_q
        self.global_settings = global_settings
        self.stop_event = threading.Event()
        self._writes = 0

    def stop(self) -> None:
        self.stop_event.set()

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                r = self.history_q.get(timeout=0.25)
            except queue.Empty:
                continue

            try:
                insert_access_history(
                    event_id=r.event_id,
                    device_id=r.device_id,
                    door_id=r.door_id,
                    card_no=r.card_no,
                    event_time=r.event_time,
                    event_type=r.event_type,
                    allowed=r.allowed,
                    reason=r.reason,
                    poll_ms=r.poll_ms,
                    decision_ms=r.decision_ms,
                    cmd_ms=r.cmd_ms,
                    cmd_ok=r.cmd_ok,
                    cmd_error=r.cmd_error,
                    raw=r.raw,
                )
            except Exception as e:
                self.logger.warning(f"[RT][history write failed] {e}")

            self._writes += 1
            if self._writes % 200 == 0:
                try:
                    g = self.global_settings() or {}
                    days = _safe_int(g.get("history_retention_days"), 30)
                    deleted = prune_access_history(retention_days=days)
                    if deleted > 0:
                        self.logger.info(f"[RT] history pruned: {deleted} rows (retention_days={days})")
                except Exception:
                    pass
                # M-008: Also clean up old offline creation queue entries
                try:
                    from app.core.db import prune_offline_creation_queue
                    oq_deleted = prune_offline_creation_queue(retention_days=30)
                    if oq_deleted > 0:
                        self.logger.info(f"[RT] offline queue pruned: {oq_deleted} rows")
                except Exception:
                    pass


# ===================== Agent realtime engine =====================

class AgentRealtimeEngine:
    """
    IMPORTANT CHANGE (Mar 2026):
    - No more local config.json for agent_global / agent_devices settings.
    - Everything (global + per-device) is read from backend DTOs cached in SQLite:
      - GymAccessSoftwareSettingsDto (global)
      - GymDeviceDto (per device)
    - Data mode is PER DEVICE (GymDevice.accessDataMode). This engine only runs on devices with accessDataMode=AGENT.
    """

    def __init__(self, *, cfg, logger):
        self.cfg = cfg  # kept for legacy; not used for settings anymore
        self.logger = logger

        self._lock = threading.Lock()
        self._running = False

        # built at start() using backend global settings
        self._event_q: "queue.Queue[AccessEvent]" = queue.Queue(maxsize=5000)
        self._notify_q: "queue.Queue[NotificationRequest]" = queue.Queue(maxsize=5000)
        self._popup_q: "queue.Queue[NotificationRequest]" = queue.Queue(maxsize=5000)
        self._history_q: "queue.Queue[HistoryRecord]" = queue.Queue(maxsize=5000)
        self._popup_capture_lock = threading.Lock()
        self._popup_events_lock = threading.Lock()
        self._popup_events_seq = 0
        self._popup_events_replay: Deque[tuple[int, Dict[str, Any]]] = deque(maxlen=128)

        self._statuses: Dict[int, DeviceStatus] = {}
        self._workers: Dict[int, DeviceWorker] = {}
        self._devices_by_id: Dict[int, Dict[str, Any]] = {}

        self._decision_ema = EMA(alpha=0.2)

        self._notif: Optional[NotificationService] = None
        self._hist: Optional[HistoryService] = None

        self._cmd_bus = DeviceCommandBus(workers_provider=self._get_worker)
        self._deciders: List[DecisionService] = []
        self._notify_gate = NotificationGate(global_settings=self.get_global_settings)

        # cache devices list (avoid hitting sqlite too often)
        self._devices_cache_at = 0.0
        self._devices_cache: List[Dict[str, Any]] = []
        self._devices_cache_ttl_sec = 1.0

        self._global_cache_at = 0.0
        self._global_cache: Dict[str, Any] = {}
        self._global_cache_ttl_sec = 2.0

    # ---------- settings providers (SQLite cached) ----------


    def _load_devices_cached(self) -> List[Dict[str, Any]]:
        """
        Primary: normalized table -> list_sync_devices_payload() (GymDeviceDto-shaped dicts).
        Fallback: raw sync_cache.payload_json (older DBs / before first sync).
        """
        now_s = time.time()
        if (now_s - float(self._devices_cache_at)) < float(self._devices_cache_ttl_sec) and self._devices_cache:
            return [dict(x) for x in self._devices_cache]

        devs: List[Dict[str, Any]] = []

        # Primary source of truth: normalized tables -> GymDeviceDto payload
        try:
            from app.core.db import list_sync_devices_payload
            rows = list_sync_devices_payload()
            if isinstance(rows, list):
                devs = [d for d in rows if isinstance(d, dict)]
        except Exception:
            devs = []

        # Fallback: raw payload_json (only if normalized tables empty)
        if not devs:
            try:
                from app.core.db import get_conn
                with get_conn() as conn:
                    r = conn.execute("SELECT payload_json FROM sync_cache WHERE id=1").fetchone()
                    if r:
                        raw = r["payload_json"]  # type: ignore[index]
                        data = json.loads(raw or "{}")
                        rows = data.get("devices") or data.get("device") or []
                        if isinstance(rows, list):
                            devs = [d for d in rows if isinstance(d, dict)]
            except Exception:
                devs = []

        self._devices_cache = devs
        self._devices_cache_at = now_s
        return [dict(x) for x in devs]

    def get_global_settings(self) -> Dict[str, Any]:
        """
        Returns normalized global settings (snake_case) from GymAccessSoftwareSettingsDto.
        Source of truth: sync_access_software_settings (SQLite).
        """
        now_s = time.time()
        with self._lock:
            if (now_s - float(self._global_cache_at)) < float(self._global_cache_ttl_sec) and self._global_cache:
                return dict(self._global_cache)

        try:
            gs = _get_backend_global_settings() or {}
            if not isinstance(gs, dict):
                gs = {}
        except Exception:
            gs = {}

        with self._lock:
            self._global_cache = gs
            self._global_cache_at = now_s
        return dict(gs)

    def _device_settings(self, device_id: int) -> Dict[str, Any]:
        did = int(device_id)
        with self._lock:
            dev = self._devices_by_id.get(did)

        gs = self.get_global_settings()
        if not isinstance(dev, dict):
            # safe defaults if device not found
            return _normalize_device_settings({"id": did, "active": False, "accessDevice": False}, gs)
        return _normalize_device_settings(dev, gs)

    def _resolve_device_name(self, device_id: int) -> str:
        """Resolve device name from cached device payloads."""
        did = int(device_id)
        with self._lock:
            dev = self._devices_by_id.get(did)
        if isinstance(dev, dict):
            return _safe_str(dev.get("name") or dev.get("deviceName"), f"device-{did}")
        return f"device-{did}"

    # ---------- engine info ----------

    def is_running(self) -> bool:
        with self._lock:
            return bool(self._running)

    def get_queue_depth(self) -> int:
        try:
            return int(self._event_q.qsize())
        except Exception:
            return 0

    def get_avg_decision_ms(self) -> float:
        return float(self._decision_ema.value if self._decision_ema.ready else 0.0)

    def get_popup_queue(self) -> "queue.Queue[NotificationRequest]":
        return self._popup_q

    def _resize_popup_replay_buffer(self, max_events: int) -> None:
        size = max(16, min(int(max_events), 1000))
        with self._popup_events_lock:
            self._popup_events_replay = deque(self._popup_events_replay, maxlen=size)

    def capture_popup_events(self, limit: int = 50) -> int:
        drained = 0
        target = max(1, _safe_int(limit, 50))
        with self._popup_capture_lock:
            while drained < target:
                try:
                    req = self._popup_q.get_nowait()
                except queue.Empty:
                    break
                except Exception:
                    break
                payload = _popup_payload_from_request(req)
                with self._popup_events_lock:
                    self._popup_events_seq += 1
                    self._popup_events_replay.append((self._popup_events_seq, payload))
                drained += 1
        return drained

    def get_latest_popup_event_seq(self) -> int:
        self.capture_popup_events(limit=100)
        with self._popup_events_lock:
            return int(self._popup_events_seq)

    def get_popup_events_since(self, seq: int, limit: int = 10) -> List[tuple[int, Dict[str, Any]]]:
        target = max(1, _safe_int(limit, 10))
        self.capture_popup_events(limit=max(target * 2, 10))
        with self._popup_events_lock:
            rows = [(event_seq, dict(payload)) for event_seq, payload in self._popup_events_replay if event_seq > seq]
        return rows[:target]

    def get_status_snapshot(self) -> Dict[int, Dict[str, Any]]:
        with self._lock:
            snap = {}
            for did, st in self._statuses.items():
                snap[did] = {
                    "deviceId": did,
                    "name": st.name,
                    "enabled": bool(st.enabled),
                    "connected": bool(st.connected),
                    "lastError": st.last_error,
                    "lastEventAt": st.last_event_at,
                    "lastPollMs": st.last_poll_ms,
                    "polls": st.polls,
                    "events": st.events,
                    "reconnects": st.reconnects,
                    "pollEma": st.poll_ema,
                    "cmdEma": st.cmd_ema,
                    "droppedEvents": st.dropped_events,
                }
            return snap

    def _get_worker(self, device_id: int) -> Optional[DeviceWorker]:
        with self._lock:
            return self._workers.get(int(device_id))

    def _status_update(self, st: DeviceStatus) -> None:
        with self._lock:
            self._statuses[int(st.device_id)] = st

    def apply_device_settings(self, device_id: int) -> None:
        did = int(device_id)
        with self._lock:
            worker = self._workers.get(did)
        if worker:
            worker.wake_event.set()

    # ---------- lifecycle ----------

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True

        self.logger.info("[RT] AgentRealtimeEngine starting (backend-driven settings)...")

        g = self.get_global_settings()

        # rebuild queues using backend sizes (safe because start() happens before workers exist)
        self._event_q = queue.Queue(maxsize=int(g.get("event_queue_max", 5000)))
        self._notify_q = queue.Queue(maxsize=int(g.get("notification_queue_max", 5000)))
        self._popup_q = queue.Queue(maxsize=int(g.get("popup_queue_max", g.get("notification_queue_max", 5000))))
        self._history_q = queue.Queue(maxsize=int(g.get("history_queue_max", 5000)))
        self._resize_popup_replay_buffer(
            max_events=int(g.get("popup_queue_max", g.get("notification_queue_max", 5000)))
        )

        self._decision_ema = EMA(alpha=float(g.get("decision_ema_alpha", 0.2)))

        self._notify_gate = NotificationGate(global_settings=self.get_global_settings)

        self._notif = NotificationService(
            logger=self.logger,
            notify_q=self._notify_q,
            global_settings=self.get_global_settings,
        )
        self._hist = HistoryService(
            logger=self.logger,
            history_q=self._history_q,
            global_settings=self.get_global_settings,
        )

        if bool(g.get("notification_service_enabled", True)):
            try:
                self._notif.start()
                self.logger.info("[RT] Notification service started")
            except Exception as e:
                self.logger.error(f"[RT] Failed to start notification service: {e}")
        else:
            self.logger.info("[RT] Notification service disabled by backend settings")

        # H-002: HistoryService is not used in AGENT mode — DecisionService writes
        # history directly via insert_access_history(). HistoryService is only needed
        # for ULTRA mode (where UltraDeviceWorker enqueues to history_q).
        # Skipping start here to avoid running an idle thread.
        self.logger.info("[RT] History service not started (AGENT mode writes history directly)")

        decider_count = _safe_int(g.get("decision_workers", 1), 1)
        if decider_count < 1:
            decider_count = 1

        self._deciders = []
        for _ in range(int(decider_count)):
            d = DecisionService(
                logger=self.logger,
                event_queue=self._event_q,
                command_bus=self._cmd_bus,
                notify_q=self._notify_q,
                popup_q=self._popup_q,
                history_q=self._history_q,
                settings_provider=self._device_settings,
                global_settings=self.get_global_settings,
                notify_gate=self._notify_gate,
                decision_ema=self._decision_ema,
                device_name_provider=self._resolve_device_name,
            )
            self._deciders.append(d)
            try:
                d.start()
            except Exception:
                pass

        self.refresh_devices()

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False

        with self._lock:
            workers = list(self._workers.values())
            deciders = list(self._deciders)
            self._workers = {}
            self._devices_by_id = {}

        for w in workers:
            try:
                w.stop()
            except Exception:
                pass

        for d in deciders:
            try:
                d.stop()
            except Exception:
                pass

        try:
            if self._notif:
                self._notif.stop()
                self._notif.join(timeout=2.0)
        except Exception:
            pass
        try:
            if self._hist:
                self._hist.stop()
                self._hist.join(timeout=2.0)
        except Exception:
            pass

        for w in workers:
            try:
                w.join(timeout=1.0)
            except Exception:
                pass

        for d in deciders:
            try:
                d.join(timeout=1.0)
            except Exception:
                pass

        self._deciders = []
        self._notif = None
        self._hist = None

    # ---------- device orchestration (per-device mode) ----------

    def refresh_devices(self) -> None:
        """
        Build workers ONLY for devices where:
          - active == true
          - accessDevice == true
          - accessDataMode == "AGENT"
        Devices in DEVICE mode are ignored here.
        """
        devices = self._load_devices_cached()

        # index by id
        devices_by_id: Dict[int, Dict[str, Any]] = {}
        for dev in devices:
            did = _safe_int(dev.get("id"), 0)
            if did <= 0:
                continue
            devices_by_id[int(did)] = dev

        self.logger.info("[RT] refresh_devices: total devices in cache=%d", len(devices_by_id))

        desired_agent_ids: set[int] = set()
        for did, dev in devices_by_id.items():
            dev_name = dev.get("name", f"device-{did}")
            # support both keys (but payload from list_sync_devices_payload is camelCase)
            if not _boolish(dev.get("active", True), True):
                self.logger.info("[RT] device id=%s name=%r skipped: active=False", did, dev_name)
                continue

            access_device_val = dev.get("accessDevice", dev.get("access_device", True))
            if not _boolish(access_device_val, True):
                self.logger.info("[RT] device id=%s name=%r skipped: accessDevice=False", did, dev_name)
                continue

            mode = _normalize_access_data_mode(dev.get("accessDataMode") or dev.get("access_data_mode"))
            if mode != "AGENT":
                self.logger.info(
                    "[RT] device id=%s name=%r skipped: accessDataMode=%r (not AGENT)", did, dev_name, mode
                )
                continue

            desired_agent_ids.add(int(did))
            self.logger.info("[RT] device id=%s name=%r: will run AGENT worker", did, dev_name)

        with self._lock:
            existing_ids = set(self._workers.keys())
            self._devices_by_id = devices_by_id

        # Start / keep workers
        for did in sorted(desired_agent_ids):
            w = self._get_worker(did)
            if not w:
                dev = devices_by_id.get(did) or {"id": did, "name": f"device-{did}"}
                self.logger.info(
                    "[RT] starting NEW DeviceWorker for device id=%s name=%r",
                    did, dev.get("name", f"device-{did}"),
                )
                w = DeviceWorker(
                    device_payload=dev,
                    logger=self.logger,
                    event_queue=self._event_q,
                    status_cb=self._status_update,
                    settings_provider=self._device_settings,
                )
                with self._lock:
                    self._workers[did] = w
                try:
                    w.start()
                    self.logger.info("[RT] DeviceWorker thread started for device id=%s", did)
                except Exception as _start_exc:
                    self.logger.error(
                        "[RT] DeviceWorker thread start FAILED for device id=%s: %s", did, _start_exc
                    )
            else:
                w.wake_event.set()

        # Stop workers removed / not in AGENT anymore
        to_remove = existing_ids - desired_agent_ids
        for did in sorted(to_remove):
            w = self._get_worker(did)
            if w:
                self.logger.info(
                    "[RT] stopping DeviceWorker for device id=%s (removed or mode changed)", did
                )
                try:
                    w.stop()
                except Exception:
                    pass
                with self._lock:
                    self._workers.pop(did, None)
                self._status_update(
                    DeviceStatus(
                        device_id=did,
                        name=getattr(w, "device_name", f"device-{did}"),
                        enabled=False,
                        connected=False,
                        last_error="removed_or_not_agent_mode",
                    )
                )

    def set_device_enabled(self, device_id: int, enabled: bool) -> None:
        """
        DEPRECATED — Device enable/disable is controlled by the backend
        (GymDeviceDto.active + GymDeviceDto.accessDataMode).
        Local overrides are not persistent and will be reversed on the next
        refresh_devices() call. Use the backend dashboard to enable/disable devices.
        Calling this method has no effect.
        """
        self.logger.warning(
            f"[RT] set_device_enabled(device_id={device_id}, enabled={enabled}) called "
            f"but has no effect — device state is controlled by backend settings. "
            f"Use refresh_devices() to sync latest backend state."
        )

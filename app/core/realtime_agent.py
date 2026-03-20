# app/core/realtime_agent.py
import hashlib
import hmac
import struct
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


def _parse_event_time_to_epoch(s: str) -> Optional[float]:
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
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp()
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


# ===================== TOTP (QR) =====================

def _totp_counter(unix_time: int, period: int) -> int:
    return int(unix_time) // int(period)


def _totp_is_hex(s: str) -> bool:
    s = (s or "").strip()
    if not s:
        return False
    if s.startswith(("0x", "0X")):
        s = s[2:]
    if len(s) % 2 != 0:
        return False
    try:
        bytes.fromhex(s)
        return True
    except Exception:
        return False


def _totp_hex_to_bytes(s: str) -> bytes:
    s = (s or "").strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    return bytes.fromhex(s)


def _totp_hotp(secret: bytes, counter: int, digits: int) -> str:
    msg = struct.pack(">Q", int(counter))
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return str(code_int % (10 ** int(digits))).zfill(int(digits))


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


# ===================== dataclasses =====================

@dataclass
class AccessEvent:
    event_id: str
    device_id: int
    door_id: Optional[int]
    event_type: str
    card_no: str
    event_time: str
    raw: Dict[str, Any]
    poll_ms: float


@dataclass
class CommandResult:
    ok: bool
    error: str
    cmd_ms: float


@dataclass
class NotificationRequest:
    event_id: str
    title: str
    message: str
    image_path: str = ""  # can be URL or local path
    popup_show_image: bool = True  # NEW: respect device.popupShowImage
    # ── enriched user/device data for Tauri popup screen ──
    user_full_name: str = ""
    user_image: str = ""
    user_valid_from: str = ""
    user_valid_to: str = ""
    user_membership_id: Optional[int] = None
    user_phone: str = ""
    device_id: int = 0
    device_name: str = ""
    allowed: bool = False
    reason: str = ""
    scan_mode: str = ""
    popup_duration_sec: int = 3
    popup_enabled: bool = True
    win_notify_enabled: bool = True


@dataclass
class HistoryRecord:
    event_id: str
    device_id: int
    door_id: Optional[int]
    card_no: str
    event_time: str
    event_type: str
    allowed: bool
    reason: str
    poll_ms: float
    decision_ms: float
    cmd_ms: float
    cmd_ok: bool
    cmd_error: str
    raw: Dict[str, Any]


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
            # dedupe
            if dedupe > 0:
                last = self._recent.get(key)
                if last is not None and (now - float(last)) < float(dedupe):
                    return False
                self._recent[key] = now

                # prune old recent entries opportunistically
                if len(self._recent) > 5000:
                    cut = now - float(dedupe) - 5.0
                    for k, t in list(self._recent.items())[:2000]:
                        if t < cut:
                            self._recent.pop(k, None)

            # rate limit
            if rate == 0:
                return False

            cutoff = now - 60.0
            while self._times and self._times[0] < cutoff:
                self._times.popleft()

            if len(self._times) >= rate:
                return False

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

        # replay protection (in-memory LRU) + persisted cursor (db)
        self._seen: Deque[str] = deque(maxlen=2000)

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
                self._last_event_epoch = _parse_event_time_to_epoch(self._last_event_at_str)
                if self._last_event_id:
                    self._seen.append(self._last_event_id)
        except Exception:
            pass

        self._polls = 0
        self._events = 0
        self._reconnects = 0

        # EMA tracking for performance
        self._poll_ema = EMA(alpha=0.2)
        self._cmd_ema = EMA(alpha=0.2)

        # Exponential backoff tracking (connect)
        self._reconnect_backoff = 0.25
        self._max_reconnect_backoff = 30.0

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

        epoch = _parse_event_time_to_epoch(event_time_str)
        if epoch is None or self._last_event_epoch is None:
            return False

        if epoch < self._last_event_epoch:
            return True

        return False

    def _maybe_flush_state(self) -> None:
        if not self._state_dirty:
            return
        now_s = time.time()
        if (now_s - self._last_state_flush_s) < 1.0:
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
        reconnect_count = 0
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
                except Exception:
                    ok = False

                if not ok:
                    reconnect_count += 1
                    self._reconnects += 1
                    last_error = "connect failed"
                    self._emit_status(enabled=True, connected=False, last_error=last_error)

                    backoff = min(self._max_reconnect_backoff, self._reconnect_backoff * (2 ** reconnect_count))
                    time.sleep(backoff)
                    continue

                reconnect_count = 0
                self._reconnect_backoff = 0.25
                last_error = ""
                self._emit_status(enabled=True, connected=True, last_error="")

            poll_t0 = _now_ms()
            try:
                rows = self._device.poll_rtlog_once()
                poll_ms = _now_ms() - poll_t0
                self._polls += 1
                self._poll_ema.add(poll_ms)

                # adaptive sleep knobs
                adaptive_sleep = bool(settings.get("adaptive_sleep", True))
                busy_min = float(_safe_int(settings.get("busy_sleep_min_ms"), 0))
                busy_max = float(_safe_int(settings.get("busy_sleep_max_ms"), 50))
                if busy_max < busy_min:
                    busy_max = busy_min

                empty_min = float(_safe_int(settings.get("empty_sleep_min_ms"), 200))
                empty_max = float(_safe_int(settings.get("empty_sleep_max_ms"), 500))
                if empty_max < empty_min:
                    empty_max = empty_min

                empty_factor = float(_safe_float(settings.get("empty_backoff_factor"), 1.35))
                if empty_factor < 1.0:
                    empty_factor = 1.0
                if empty_factor > 3.0:
                    empty_factor = 3.0

                empty_backoff_max = float(_safe_int(settings.get("empty_backoff_max_ms"), 2000))
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

                        if access_history_exists(event_id):
                            continue

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
                        )

                        try:
                            self.event_queue.put(ev, timeout=0.05)
                        except Exception:
                            pass

                        self._last_event_id = event_id
                        self._last_event_at_str = event_time_str or self._last_event_at_str
                        ep = _parse_event_time_to_epoch(event_time_str)
                        if ep is not None:
                            self._last_event_epoch = ep
                        self._state_dirty = True

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
                if adaptive_sleep and busy_max > 0:
                    sleep_ms = max(0.0, min(busy_max, max(busy_min, busy_min)))
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
        self._cache_ttl_sec = 2.0

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
        now_s = time.time()

        def add_card(idx: Dict[str, List[Dict[str, Any]]], v: Any, u: Dict[str, Any]) -> None:
            if v is None:
                return
            s = str(v).strip()
            if not s:
                return
            if s.isdigit():
                idx.setdefault(s, []).append(u)

        def add_cards_from_obj(idx: Dict[str, List[Dict[str, Any]]], obj: Any, u: Dict[str, Any]) -> None:
            if not isinstance(obj, dict):
                return
            for k in ("firstCardId", "cardId", "secondCardId", "cardNo", "rfid", "rfidCard", "rfidCardNo", "cardNumber"):
                if k in obj:
                    add_card(idx, obj.get(k), u)

        with self._cache_lock:
            if ttl <= 0 or (now_s - float(self._creds_cache_at)) > ttl:
                try:
                    self._creds_cache = list_sync_gym_access_credentials()
                except Exception:
                    self._creds_cache = []
                self._creds_cache_at = now_s

            if ttl <= 0 or (now_s - float(self._users_cache_at)) > ttl:
                try:
                    users = list_sync_users()
                except Exception:
                    users = []

                idx_by_am: Dict[int, Dict[str, Any]] = {}
                idx_by_card: Dict[str, List[Dict[str, Any]]] = {}

                for u in users:
                    if not isinstance(u, dict):
                        continue

                    am_id = u.get("activeMembershipId")
                    try:
                        if am_id is not None:
                            s = str(am_id).strip()
                            if s:
                                idx_by_am[int(s)] = u
                    except Exception:
                        pass

                    add_cards_from_obj(idx_by_card, u, u)

                    for nested_key in ("activeMembership", "activeMembershipModel", "activeMembershipDto"):
                        nested = u.get(nested_key)
                        add_cards_from_obj(idx_by_card, nested, u)

                    cards = u.get("cards")
                    if isinstance(cards, list):
                        for c in cards:
                            add_card(idx_by_card, c, u)

                self._users_by_active_membership_id = idx_by_am
                self._users_by_card = idx_by_card
                self._users_cache_at = now_s

            return list(self._creds_cache), dict(self._users_by_active_membership_id), dict(self._users_by_card)

    def _verify_card(
        self,
        *,
        scanned: str,
        settings: Dict[str, Any],
        users_by_card: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()

        if not bool(settings.get("rfid_enabled", True)):
            return {
                "allowed": False,
                "reason": "DENY_RFID_DISABLED",
                "scanMode": "RFID_CARD",
                "tookMs": (time.perf_counter() - t0) * 1000.0,
                "user": None,
            }

        code = (scanned or "").strip()
        if (not code) or (not code.isdigit()):
            return {
                "allowed": False,
                "reason": "INVALID_CARD_FORMAT",
                "scanMode": "RFID_CARD",
                "tookMs": (time.perf_counter() - t0) * 1000.0,
                "user": None,
            }

        # Backend supports 1..16 digits
        min_len = _safe_int(settings.get("rfid_min_digits"), 1)
        max_len = _safe_int(settings.get("rfid_max_digits"), 16)

        if min_len < 1:
            min_len = 1
        if max_len > 16:
            max_len = 16
        if max_len < min_len:
            max_len = min_len

        if not (min_len <= len(code) <= max_len):
            return {
                "allowed": False,
                "reason": "INVALID_CARD_LENGTH",
                "scanMode": "RFID_CARD",
                "minDigits": int(min_len),
                "maxDigits": int(max_len),
                "tookMs": (time.perf_counter() - t0) * 1000.0,
                "user": None,
            }

        hits = users_by_card.get(code) or []
        if not hits:
            return {
                "allowed": False,
                "reason": "DENY_NO_CARD_MATCH",
                "scanMode": "RFID_CARD",
                "tookMs": (time.perf_counter() - t0) * 1000.0,
                "user": None,
            }

        if len(hits) != 1:
            return {
                "allowed": False,
                "reason": "DENY_CARD_COLLISION",
                "scanMode": "RFID_CARD",
                "count": len(hits),
                "tookMs": (time.perf_counter() - t0) * 1000.0,
                "user": None,
            }

        user = hits[0]
        am_id = user.get("activeMembershipId")
        try:
            am_id = int(str(am_id).strip()) if am_id is not None else None
        except Exception:
            am_id = None

        return {
            "allowed": True,
            "reason": "ALLOW_CARD",
            "scanMode": "RFID_CARD",
            "activeMembershipId": am_id,
            "user": user,
            "tookMs": (time.perf_counter() - t0) * 1000.0,
        }

    def _verify_totp(
        self,
        *,
        scanned: str,
        settings: Dict[str, Any],
        creds_payload: List[Dict[str, Any]],
        users_by_am: Dict[int, Dict[str, Any]],
        users_by_card: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()

        totp_enabled = bool(settings.get("totp_enabled", True))

        period = _safe_int(settings.get("totp_period_seconds", 30))
        drift = _safe_int(settings.get("totp_drift_steps", 1))
        max_past_age = _safe_int(settings.get("totp_max_past_age_seconds", 32))
        max_future_skew = _safe_int(settings.get("totp_max_future_skew_seconds", 3))

        prefix = _safe_str(settings.get("totp_prefix", "9"), "9").strip()
        if (len(prefix) != 1) or (not prefix.isdigit()):
            prefix = "9"

        digits = _safe_int(settings.get("totp_digits", 7))
        if digits < 4:
            digits = 4
        if digits > 10:
            digits = 10

        expected_len = 1 + int(digits)  # prefix + digits

        raw = (scanned or "").strip()

        if not totp_enabled:
            return {
                "allowed": True,
                "reason": "ALLOW_BYPASS_TOTP_DISABLED",
                "scanMode": "BYPASS",
                "tookMs": (time.perf_counter() - t0) * 1000.0,
                "user": None,
            }

        if (not raw) or (not raw.isdigit()):
            return {
                "allowed": False,
                "reason": "INVALID_FORMAT",
                "scanMode": "UNKNOWN",
                "tookMs": (time.perf_counter() - t0) * 1000.0,
                "user": None,
            }

        # If code doesn't match expected QR format => treat as RFID directly
        if len(raw) != expected_len or (not raw.startswith(prefix)):
            vr = self._verify_card(scanned=raw, settings=settings, users_by_card=users_by_card)
            if bool(vr.get("allowed", False)):
                vr["scanMode"] = "RFID_DIRECT"
            return vr

        # QR TOTP format => use LAST 'digits'
        code = raw[-digits:]

        now = int(time.time())
        cur = _totp_counter(now, period)
        allowed_ctrs = list(range(cur - int(drift), cur + int(drift) + 1))

        hits: List[Dict[str, Any]] = []
        for c in creds_payload:
            if not isinstance(c, dict):
                continue
            if not bool(c.get("enabled", False)):
                continue

            cred_id = c.get("id")
            account_id = c.get("accountId")
            secret_hex = (c.get("secretHex") or "").strip()
            grants = c.get("grantedActiveMembershipIds") or []

            if cred_id in (None, "", 0) or account_id in (None, "", 0):
                continue
            if not secret_hex or (not _totp_is_hex(secret_hex)):
                continue
            if not isinstance(grants, list) or not grants:
                continue

            try:
                secret = _totp_hex_to_bytes(secret_hex)
            except Exception:
                continue

            for ctr in allowed_ctrs:
                try:
                    if _totp_hotp(secret, ctr, digits) == code:
                        hits.append(
                            {
                                "credId": str(cred_id),
                                "accountId": str(account_id),
                                "counter": int(ctr),
                                "grants": list(grants),
                            }
                        )
                except Exception:
                    continue

        if hits:
            uniq_creds = sorted(set(h["credId"] for h in hits))
            if len(uniq_creds) != 1:
                return {
                    "allowed": False,
                    "reason": "DENY_COLLISION",
                    "scanMode": "QR_TOTP",
                    "tookMs": (time.perf_counter() - t0) * 1000.0,
                    "user": None,
                }

            cred_id = uniq_creds[0]
            counters = sorted(set(int(h["counter"]) for h in hits if h["credId"] == cred_id))
            if len(counters) != 1:
                return {
                    "allowed": False,
                    "reason": "DENY_AMBIGUOUS_COUNTER",
                    "scanMode": "QR_TOTP",
                    "tookMs": (time.perf_counter() - t0) * 1000.0,
                    "user": None,
                }

            matched_ctr = int(counters[0])
            age = int(now - (matched_ctr * int(period)))

            if age < -int(max_future_skew):
                return {
                    "allowed": False,
                    "reason": "DENY_FUTURE_SKEW",
                    "scanMode": "QR_TOTP",
                    "credId": cred_id,
                    "matchedCounter": matched_ctr,
                    "ageSeconds": age,
                    "tookMs": (time.perf_counter() - t0) * 1000.0,
                    "user": None,
                }

            if age > int(max_past_age):
                return {
                    "allowed": False,
                    "reason": "DENY_EXPIRED",
                    "scanMode": "QR_TOTP",
                    "credId": cred_id,
                    "matchedCounter": matched_ctr,
                    "ageSeconds": age,
                    "tookMs": (time.perf_counter() - t0) * 1000.0,
                    "user": None,
                }

            hit0 = hits[0]
            account_id = str(hit0.get("accountId") or "")
            grants = hit0.get("grants") or []

            user: Optional[Dict[str, Any]] = None
            chosen_am_id: Optional[int] = None
            for gid in grants:
                try:
                    am = int(str(gid).strip())
                except Exception:
                    continue
                if am in users_by_am:
                    user = users_by_am.get(am)
                    chosen_am_id = am
                    break
                if chosen_am_id is None:
                    chosen_am_id = am

            return {
                "allowed": True,
                "reason": "ALLOW",
                "scanMode": "QR_TOTP",
                "accountId": account_id,
                "credId": cred_id,
                "matchedCounter": matched_ctr,
                "ageSeconds": age,
                "activeMembershipId": chosen_am_id,
                "user": user,
                "tookMs": (time.perf_counter() - t0) * 1000.0,
            }

        # TOTP failed => fallback to RFID
        vr_card = self._verify_card(scanned=raw, settings=settings, users_by_card=users_by_card)
        if bool(vr_card.get("allowed", False)):
            vr_card["scanMode"] = "CARD_FALLBACK_AFTER_TOTP_FAIL"
            vr_card["reason"] = "ALLOW_CARD_FALLBACK"
            return vr_card

        return {
            "allowed": False,
            "reason": "DENY_NO_MATCH",
            "scanMode": "QR_TOTP",
            "tookMs": (time.perf_counter() - t0) * 1000.0,
            "user": None,
        }

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                ev = self.event_queue.get(timeout=0.25)
            except queue.Empty:
                continue

            settings = self.settings_provider(ev.device_id)
            t0 = _now_ms()

            creds_payload, users_by_am, users_by_card = self._load_local_state()
            vr = self._verify_totp(
                scanned=ev.card_no,
                settings=settings,
                creds_payload=creds_payload,
                users_by_am=users_by_am,
                users_by_card=users_by_card,
            )

            allowed = bool(vr.get("allowed", False))
            reason = _safe_str(vr.get("reason", "DENY"))
            scan_mode = _safe_str(vr.get("scanMode", ""), "")

            action = "OPEN_DOOR" if allowed else "NONE"
            door_id = ev.door_id if ev.door_id is not None else _safe_int(settings.get("door_entry_id"), 1)
            pulse_time_ms = _safe_int(settings.get("pulse_time_ms"), 3000)

            decision_ms = _now_ms() - t0
            self.decision_ema.add(decision_ms)

            cmd_res = CommandResult(ok=True, error="", cmd_ms=0.0)
            if action == "OPEN_DOOR":
                cmd_timeout_ms = _safe_int(settings.get("cmd_timeout_ms"), 4000)
                cmd_res = self.command_bus.open_door(
                    device_id=ev.device_id,
                    door_id=int(door_id),
                    pulse_time_ms=int(pulse_time_ms),
                    timeout_ms=int(cmd_timeout_ms),
                )

            if bool(settings.get("save_history", True)):
                try:
                    raw = dict(ev.raw)
                    raw["decision"] = {
                        "allowed": allowed,
                        "reason": reason,
                        "scanMode": scan_mode,
                        "commandDoorId": int(door_id),
                        "pulseTimeMs": int(pulse_time_ms),
                        "accountId": vr.get("accountId"),
                        "credId": vr.get("credId"),
                        "matchedCounter": vr.get("matchedCounter"),
                        "ageSeconds": vr.get("ageSeconds"),
                        "activeMembershipId": vr.get("activeMembershipId"),
                        "tookMs": vr.get("tookMs"),
                        "user": vr.get("user"),
                    }

                    self.history_q.put(
                        HistoryRecord(
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
                            cmd_ms=float(cmd_res.cmd_ms),
                            cmd_ok=bool(cmd_res.ok),
                            cmd_error=str(cmd_res.error or ""),
                            raw=raw,
                        ),
                        timeout=0.05,
                    )
                except Exception:
                    pass

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
                except Exception:
                    pass

            # Popup (Tkinter) (per-device popupEnabled)
            if bool(settings.get("popup_enabled", True)):
                try:
                    self.popup_q.put(req, timeout=0.05)
                except Exception:
                    pass


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
                    icon_path = self._img_cache.resolve(r.image_path)

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
                self.logger.debug(f"[RT][history write failed] {e}")

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
        if (now_s - float(self._global_cache_at)) < float(self._global_cache_ttl_sec) and self._global_cache:
            return dict(self._global_cache)

        try:
            gs = _get_backend_global_settings() or {}
            if not isinstance(gs, dict):
                gs = {}
        except Exception:
            gs = {}

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

        if bool(g.get("history_service_enabled", True)):
            try:
                self._hist.start()
                self.logger.info("[RT] History service started")
            except Exception as e:
                self.logger.error(f"[RT] Failed to start history service: {e}")
        else:
            self.logger.info("[RT] History service disabled by backend settings")

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

        desired_agent_ids: set[int] = set()
        for did, dev in devices_by_id.items():
            # support both keys (but payload from list_sync_devices_payload is camelCase)
            if not _boolish(dev.get("active", True), True):
                continue

            access_device_val = dev.get("accessDevice", dev.get("access_device", True))
            if not _boolish(access_device_val, True):
                continue

            mode = _normalize_access_data_mode(dev.get("accessDataMode") or dev.get("access_data_mode"))
            if mode != "AGENT":
                continue

            desired_agent_ids.add(int(did))

        with self._lock:
            existing_ids = set(self._workers.keys())
            self._devices_by_id = devices_by_id

        # Start / keep workers
        for did in sorted(desired_agent_ids):
            w = self._get_worker(did)
            if not w:
                dev = devices_by_id.get(did) or {"id": did, "name": f"device-{did}"}
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
                except Exception:
                    pass
            else:
                w.wake_event.set()

        # Stop workers removed / not in AGENT anymore
        to_remove = existing_ids - desired_agent_ids
        for did in sorted(to_remove):
            w = self._get_worker(did)
            if w:
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
        This still exists for UI toggles, but the source of truth is backend 'active' + 'accessDataMode'.
        - If enabled=True: we just refresh devices (if backend says it should run, it will).
        - If enabled=False: we stop local worker (temporary), but next refresh will recreate it unless backend changes.
        """
        did = int(device_id)
        if enabled:
            self.refresh_devices()
            return

        w = self._get_worker(did)
        if w:
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
                    last_error="disabled_locally",
                )
            )

"""What the front desk hears and sees for one ULTRA scan besides the entry popup (ULTRA merge, spec
2026-10-02 section 5, D4; plan 3).

- The feedback bus. The desk's sound events (the Tauri AccessFeedbackProvider reads them from
  GET /api/v2/feedback/events). Moved here from MainApp.publish_feedback_event /
  get_feedback_events_since (app/ui/app.py), which now call it, so an ULTRA worker can emit without
  a callback threaded through UltraEngine: MainApp installs its bus (install_bus) and emit() posts
  to it.
- The repeat-block sound. A scan refused by the member block (reason DENY_REPEAT_BLOCK,
  repeat_guard.py) emits ``anti_fraud_duration``, the event AGENT emits for its anti-fraud refusals
  (realtime_agent.py) and the desk already plays (its per-PC switch "Anti-fraude durée"). Plan 3
  OD-2: no other refusal rings in release 1.
- The daily pass alert. An allowed entry that takes the member's count today on this device and
  door ABOVE ``anti_fraude_daily_pass_limit`` emits ``anti_fraud_daily_limit`` (AGENT's alert,
  realtime_agent.py). Alert only: it never blocks. The count is the history
  (db.count_today_for_user_door) plus the scan in flight, which ULTRA writes asynchronously; with
  Keep entry history off there is no count and no alert, as in AGENT.
- The frequent-pass badge's count (moved from UltraDeviceWorker._enqueue_notification unchanged).
- The Windows toast. One per decided scan when the device's ``win_notify_enabled`` is on, shown on
  this module's own thread (winotify, as AGENT's NotificationService does) so the worker loop never
  waits for it.

Every entry point is best-effort and never raises: nothing here takes part in an access decision.
"""
from __future__ import annotations

import logging
import os
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from app.core import telemetry as _tel
from app.core.device_service_gate import keeps_history

logger = logging.getLogger("zkapp")

# The feedback event types the desk already plays (tauri-ui AccessFeedbackProvider.tsx
# ACCEPTED_EVENT_TYPES, lib/feedback.ts). A new type would need a desk UI release.
EVENT_REPEAT = "anti_fraud_duration"
EVENT_DAILY = "anti_fraud_daily_limit"

# The refusals that ring in release 1 (plan 3 OD-2): the member block only.
SOUND_REASONS = frozenset({"DENY_REPEAT_BLOCK"})


# ------------------------------------------------------------------ the feedback bus
class FeedbackBus:
    """The desk's feedback events, newest last, the last ``KEEP`` kept (was MainApp's)."""

    KEEP = 200

    def __init__(self) -> None:
        self._seq = 0
        self._events: List[Dict[str, Any]] = []
        self._cond = threading.Condition()

    def publish(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._cond:
            self._seq += 1
            event = {
                "seq": self._seq,
                "type": str(event_type or "").strip(),
                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                **dict(payload or {}),
            }
            self._events.append(event)
            if len(self._events) > self.KEEP:
                self._events = self._events[-self.KEEP:]
            self._cond.notify_all()
            return dict(event)

    def since(self, seq: int, *, limit: int = 20) -> List[Dict[str, Any]]:
        with self._cond:
            threshold = int(seq or 0)
            capped_limit = max(1, min(int(limit or 20), 100))
            items = [dict(event) for event in self._events if int(event.get("seq") or 0) > threshold]
            return items[:capped_limit]


_bus: Optional[FeedbackBus] = None


def install_bus(bus: Optional[FeedbackBus]) -> Optional[FeedbackBus]:
    """Make ``bus`` the one emit() posts to (MainApp.__init__). Returns the previous one."""
    global _bus
    previous, _bus = _bus, bus
    return previous


def emit(event_type: str, payload: Dict[str, Any]) -> bool:
    """Post one feedback event to the installed bus. False when none is installed or it failed."""
    bus = _bus
    if bus is None:
        return False
    try:
        bus.publish(event_type, payload)
        return True
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("[DESK] feedback emit failed type=%s: %s", event_type, exc)
        return False


# ------------------------------------------------------------------ alerts
def refusal_sound(
    settings: Dict[str, Any], *, allowed: bool, reason: str, device_id: int, device_name: str,
    door_id: Optional[int], user_id: Optional[int], user_full_name: str,
) -> bool:
    """Emit the repeat-block sound for a refused scan whose reason rings (SOUND_REASONS)."""
    if allowed or str(reason or "").strip().upper() not in SOUND_REASONS:
        return False
    sent = emit(EVENT_REPEAT, {
        "user_id": user_id,
        "full_name": str(user_full_name or ""),
        "device_id": int(device_id),
        "device_name": str(device_name or ""),
        "door_id": door_id,
        "card_no": "",
        # Not known here; the desk reads only the event's type (AccessFeedbackProvider.tsx).
        "remaining_seconds": 0.0,
        "reason": str(reason),
    })
    if sent:
        _tel.event("DESK_SOUND", device=int(device_id), reason=str(reason), door=door_id)
    return sent


def daily_alert(
    settings: Dict[str, Any], *, allowed: bool, device_id: int, device_name: str,
    door_id: Optional[int], user_id: Optional[int], user_full_name: str,
    count_today: Optional[Callable[..., int]] = None,
) -> Optional[Dict[str, Any]]:
    """The daily pass alert of one allowed entry; the payload emitted, or None. Never blocks."""
    try:
        limit = int(settings.get("anti_fraude_daily_pass_limit") or 0)
    except (TypeError, ValueError):
        limit = 0
    if not allowed or limit <= 0 or user_id is None or door_id is None:
        return None
    if not keeps_history(settings):
        return None  # the count is the history: none is written for this device (AGENT parity)
    if count_today is None:
        from app.core.db import count_today_for_user_door as count_today
    try:
        # +1: ULTRA writes this scan's history row after this call, asynchronously.
        count = int(count_today(user_id=int(user_id), device_id=int(device_id), door_id=int(door_id))) + 1
    except Exception as exc:
        logger.warning("[DESK] daily count failed device=%s user=%s door=%s: %s",
                       device_id, user_id, door_id, exc)
        return None
    if count <= limit:
        return None
    payload = {
        "user_id": int(user_id),
        "full_name": str(user_full_name or ""),
        "count_today": count,
        "limit": limit,
        "device_id": int(device_id),
        "device_name": str(device_name or ""),
        "door_id": int(door_id),
    }
    emit(EVENT_DAILY, payload)
    _tel.event("DESK_DAILY_ALERT", device=int(device_id), door=int(door_id), count=count, limit=limit)
    return payload


def frequent_pass(
    settings: Dict[str, Any], *, allowed: bool, user_id: Optional[int], device_id: int,
    door_id: Optional[int], prefix: str = "", count_recent: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """The frequent-pass VISUAL alert's popup fields (X passages inside Y minutes), moved unchanged
    from UltraDeviceWorker._enqueue_notification. THIS NEVER BLOCKS: the caller settled `allowed`
    and the door before; nothing here is read back into a decision."""
    rep_count, rep_limit, rep_window, prev_at = 0, 0, 0, ""
    try:
        rep_limit = int(settings.get("frequent_pass_limit") or 0)
        rep_window = int(settings.get("frequent_pass_window_minutes") or 0)
        if allowed and rep_limit > 1 and rep_window > 0 and user_id is not None and door_id is not None:
            if count_recent is None:
                from app.core.db import count_recent_for_user_door as count_recent
            prior, prev_raw = count_recent(
                user_id=int(user_id), device_id=int(device_id), door_id=int(door_id),
                window_minutes=rep_window,
            )
            # ULTRA persists history asynchronously (_enqueue_history is drained on a later tick),
            # so the scan being handled right now is NOT in access_history yet. Count it explicitly.
            total = int(prior) + 1
            if total >= rep_limit:
                rep_count = total
                prev_at = str(prev_raw or "")
    except Exception as exc:
        rep_count, prev_at = 0, ""
        logger.warning(f"{prefix} frequent-pass alert check failed: {exc}")
    return {
        "repeat_count": rep_count,
        "repeat_limit": rep_limit if rep_count else 0,
        "repeat_window_min": rep_window if rep_count else 0,
        "previous_entry_at": prev_at,
    }


# ------------------------------------------------------------------ the Windows toast
def _winotify_show(title: str, message: str, icon: str) -> None:  # pragma: no cover - real Windows
    from winotify import Notification, audio  # type: ignore

    toast = Notification(app_id="MonClub Access", title=title, msg=message, icon=icon or "")
    try:
        toast.set_audio(audio.Default, loop=False)
    except Exception:
        pass
    toast.show()


def _global_settings() -> Dict[str, Any]:
    from app.core.settings_reader import get_backend_global_settings

    return get_backend_global_settings() or {}


class ToastService:
    """One Windows toast per decided scan, shown on its own daemon thread (started on first use).
    A full queue drops the toast (``TOAST_QUEUE_FULL``): the worker never waits. The backend's global
    ``notification_service_enabled`` switches every toast off, as for AGENT."""

    QUEUE_MAX = 200

    def __init__(self, *, show: Optional[Callable[[str, str, str], None]] = None,
                 global_settings: Optional[Callable[[], Dict[str, Any]]] = None,
                 autostart: bool = True) -> None:
        self._show = show or _winotify_show
        self._autostart = bool(autostart)
        self._global = global_settings or _global_settings
        self._q: "queue.Queue[tuple]" = queue.Queue(maxsize=self.QUEUE_MAX)
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def submit(self, title: str, message: str, icon: str = "") -> bool:
        try:
            self._q.put_nowait((str(title), str(message), str(icon or "")))
        except queue.Full:
            _tel.warn("TOAST_QUEUE_FULL")
            return False
        if self._autostart:
            self._ensure_thread()
        return True

    def _ensure_thread(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._run, name="desk-toasts", daemon=True)
            self._thread.start()

    def _run(self) -> None:  # pragma: no cover - the loop around drain_once
        while True:
            try:
                item = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            self._deliver(item)

    def drain_once(self) -> int:
        """Show every queued toast now, on the calling thread (tests build the service with
        autostart=False). Returns the number shown."""
        shown = 0
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                return shown
            shown += 1 if self._deliver(item) else 0

    def _deliver(self, item: tuple) -> bool:
        title, message, icon = item
        try:
            if not bool((self._global() or {}).get("notification_service_enabled", True)):
                return False
            self._show(title, message, icon)
            _tel.event("TOAST_SHOW", title=str(title)[:30], has_icon=bool(icon))
            return True
        except Exception as exc:
            logger.debug("[DESK] toast failed: %s", exc)
            _tel.warn("TOAST_FAILED", err=type(exc).__name__)
            return False


_toasts: Optional[ToastService] = None
_toasts_lock = threading.Lock()


def toasts() -> ToastService:
    global _toasts
    with _toasts_lock:
        if _toasts is None:
            _toasts = ToastService()
        return _toasts


def _cached_icon(url: str) -> str:
    """The member's photo when the popup image cache already holds it; never a download here."""
    if not url:
        return ""
    try:
        from app.core.popup_image_cache import cache_path, normalize_url

        normalized = normalize_url(url)          # the key the prefetch caches under
        if not normalized or normalized.startswith("data:"):
            return ""
        path = cache_path(normalized)
        return path if os.path.isfile(path) else ""
    except Exception:
        return ""


def entry_toast(
    settings: Dict[str, Any], *, allowed: bool, reason: str, device_name: str,
    door_id: Optional[int], user_full_name: str, user_image: str,
    service: Optional[ToastService] = None,
) -> bool:
    """Queue the Windows toast of one decided scan when the device's switch is on."""
    if not bool(settings.get("win_notify_enabled", False)):
        return False
    title = "Access OK" if allowed else "Access DENY"
    message = f"{user_full_name or '-'} | {device_name} | door={door_id if door_id is not None else '-'}"
    if not allowed:
        message += f" | reason={reason}"
    icon = _cached_icon(user_image) if allowed else ""
    return (service or toasts()).submit(title, message, icon)


def after_scan(
    settings: Dict[str, Any], *, device_id: int, device_name: str, allowed: bool, reason: str,
    user_id: Optional[int], user_full_name: str, user_image: str, door_id: Optional[int],
    prefix: str = "",
) -> None:
    """Everything the desk gets for one decided scan besides the popup: the Windows toast, the
    daily pass alert, the repeat-block sound. Called once per scan by
    UltraDeviceWorker._enqueue_notification BEFORE its popup switch, so a device with the popup off
    still alerts (AGENT emitted its sounds before its own popup switch). Never raises."""
    steps = (
        lambda: entry_toast(settings, allowed=allowed, reason=reason, device_name=device_name,
                            door_id=door_id, user_full_name=user_full_name, user_image=user_image),
        lambda: daily_alert(settings, allowed=allowed, device_id=device_id, device_name=device_name,
                            door_id=door_id, user_id=user_id, user_full_name=user_full_name),
        lambda: refusal_sound(settings, allowed=allowed, reason=reason, device_id=device_id,
                              device_name=device_name, door_id=door_id, user_id=user_id,
                              user_full_name=user_full_name),
    )
    for step in steps:
        try:
            step()
        except Exception as exc:  # pragma: no cover - each step already guards itself
            logger.warning(f"{prefix} desk alert failed: {exc}")

"""ULTRA mode engine: device-firmware RFID/FP + PC-side RTLog observer + TOTP rescue."""

import logging
import queue
import threading
import time
from collections import deque
from types import SimpleNamespace
from typing import Any, Deque, Dict, List, Optional, Set

from app.core.access_types import HistoryRecord, NotificationRequest
from app.core.access_verification import load_local_state, verify_totp
from app.core.db import get_recent_access_history, insert_access_history, load_sync_cache
from app.sdk.pullsdk import PullSDKDevice

logger = logging.getLogger("zkapp")


# ---------------------------------------------------------------------------
# UltraDeviceWorker
# ---------------------------------------------------------------------------

class UltraDeviceWorker(threading.Thread):
    """Per-device thread: polls RTLog, classifies events, TOTP rescue."""

    def __init__(
        self,
        device: Dict[str, Any],
        settings: Dict[str, Any],
        popup_q: "queue.Queue[NotificationRequest]",
        history_q: "queue.Queue[HistoryRecord]",
        stop_event: threading.Event,
        cfg: Any | None = None,
        on_full_sync_started: Any | None = None,
        on_full_sync_finished: Any | None = None,
    ):
        super().__init__(daemon=True, name=f"UltraWorker-{device.get('id')}")
        self._device = device
        self._settings = settings
        self._popup_q = popup_q
        self._history_q = history_q
        self._stop_evt = stop_event
        self._cfg = cfg
        self._on_full_sync_started = on_full_sync_started
        self._on_full_sync_finished = on_full_sync_finished
        self._device_id = int(device.get("id", 0))
        logger.debug(
            "[ULTRA:%s] __init__: name=%r ip=%s port=%s totp=%s rfid=%s "
            "cooldown=%.1fs poll_timeout=%.1fs",
            device.get("id"), device.get("name"),
            device.get("ipAddress", "?"), device.get("portNumber", "?"),
            settings.get("totp_enabled", True), settings.get("rfid_enabled", True),
            float(settings.get("replay_block_window_seconds", 10)),
            float(settings.get("rtlog_poll_timeout_sec", 15.0)),
        )
        self._device_name = str(device.get("name", ""))
        self._sdk: Optional[PullSDKDevice] = None
        self._seen: Deque[str] = deque(maxlen=10_000)
        self._connected = False
        self._events_processed = 0
        self._totp_rescues = 0
        self._totp_failures = 0
        self._door_cmd_failures = 0
        self._poll_ema_ms = 0.0
        self._prefix = f"[ULTRA:{self._device_id}]"
        # Card-level cooldown: prevents duplicate door opens when the C3
        # controller fires multiple events for the same card/QR scan.
        # Uses anti_fraude_duration from dashboard (seconds) when available,
        # falls back to replay_block_window_seconds (default 10s).
        self._card_cooldown: Dict[str, float] = {}  # card_no -> monotonic timestamp
        _af_duration = settings.get("anti_fraude_duration")
        if _af_duration is not None and int(_af_duration) > 0:
            self._card_cooldown_sec = float(_af_duration)
        else:
            self._card_cooldown_sec = float(settings.get("replay_block_window_seconds", 10))

        # Adaptive sleep settings (same as AGENT mode)
        self._busy_min = int(settings.get("busy_sleep_min_ms", 0))
        self._busy_max = int(settings.get("busy_sleep_max_ms", 50))
        self._empty_min = int(settings.get("empty_sleep_min_ms", 200))
        self._empty_max = int(settings.get("empty_sleep_max_ms", 500))
        self._backoff = float(settings.get("empty_backoff_factor", 1.35))
        self._backoff_cap = int(settings.get("empty_backoff_max_ms", 2000))
        self._empty_sleep_ms = float(self._empty_min)
        # M-002: RTLog poll timeout configurable per-device (was hardcoded 15.0)
        self._poll_timeout_sec = float(settings.get("rtlog_poll_timeout_sec", 15.0))

        # Sync-pause handshake: set by UltraSyncScheduler before it connects to the device
        self._sync_pause = threading.Event()      # set = paused for sync
        self._sync_paused_ack = threading.Event() # set = worker confirmed disconnect

        # Command queue: door open requests executed inline between polls
        # (avoids TCP disconnect/reconnect needed by the old pause approach).
        self._cmd_queue: "queue.Queue" = queue.Queue(maxsize=10)
        self._member_sync_lock = threading.Lock()
        self._pending_member_syncs: Deque[int] = deque()
        self._pending_member_sync_ids: Set[int] = set()
        self._full_sync_lock = threading.Lock()
        self._pending_full_sync_request: Dict[str, Any] | None = None
        self._active_sync_lock = threading.Lock()
        self._active_sync_engine: Optional[Any] = None
        self._current_full_sync_reason = ""
        self._last_full_sync_started_at = ""
        self._last_full_sync_finished_at = ""
        self._last_full_sync_duration_ms = 0.0
        self._last_full_sync_error = ""
        self._full_sync_running = False

        # Local state cache (avoid per-event DB reads)
        self._cached_state: Optional[tuple] = None
        self._cached_state_ts: float = 0.0
        self._CACHE_TTL_SEC: float = 60.0  # sync data only changes on sync cycles (~60s)
        self._connect_retry_base_sec = float(settings.get("connect_retry_base_sec", 2.0))
        self._connect_retry_max_sec = float(settings.get("connect_retry_max_sec", 15.0))
        self._connect_failures = 0
        self._next_connect_at_mono = 0.0
        self._last_connect_error = ""
        self._last_connect_attempt_at = ""
        self._last_connect_success_at = ""

    def reset_fast_patch_caches(self) -> None:
        self._cached_state = None
        self._cached_state_ts = 0.0

    # ------------------------------------------------------------------ #
    # Main loop
    # ------------------------------------------------------------------ #

    def run(self):
        """Main loop: connect -> poll RTLog -> classify -> repeat."""
        logger.info(f"{self._prefix} started")
        self._pre_populate_seen()

        # Pre-warm the local state cache eagerly so the first scan doesn't
        # block for 30+ seconds loading 1,275 users from SQLite.
        try:
            self._get_cached_local_state()
            logger.info(f"{self._prefix} local state cache pre-warmed")
        except Exception as e:
            logger.warning(f"{self._prefix} cache pre-warm failed: {e} (will retry on first event)")

        while not self._stop_evt.is_set():
            try:
                # Yield the TCP connection to UltraSyncScheduler when requested
                if self._sync_pause.is_set():
                    if self._connected:
                        logger.info(
                            f"{self._prefix} sync pause requested — disconnecting for TCP handoff"
                        )
                        self._disconnect()
                    self._sync_paused_ack.set()
                    while self._sync_pause.is_set() and not self._stop_evt.is_set():
                        self._stop_evt.wait(0.5)
                    self._sync_paused_ack.clear()
                    logger.info(f"{self._prefix} sync pause ended — will reconnect")
                    # Pre-warm cache after sync invalidated it (resume_from_sync sets _cached_state=None).
                    # Without this, the first event after resume blocks 5+ seconds loading from SQLite.
                    try:
                        self._get_cached_local_state()
                    except Exception:
                        pass
                    continue

                # Connect if needed
                if not self._connected:
                    wait_sec = self._connect_wait_remaining()
                    if wait_sec > 0:
                        self._stop_evt.wait(min(wait_sec, 1.0))
                        continue
                    self._connect()
                    if not self._connected:
                        continue

                # Drain queued door-open commands (uses the already-connected SDK)
                self._drain_commands()

                # Poll RTLog with watchdog
                events = self._poll_with_watchdog()
                if events is None:
                    # Watchdog timeout or error -> reconnect
                    self._disconnect()
                    continue

                if events:
                    self._empty_sleep_ms = float(self._empty_min)
                    for evt in events:
                        self._process_event(evt)
                    sleep_ms = self._busy_min
                else:
                    self._empty_sleep_ms = min(
                        self._empty_sleep_ms * self._backoff,
                        self._backoff_cap,
                    )
                    sleep_ms = self._empty_sleep_ms

                # Drain commands again after processing events for minimal latency
                self._drain_commands()
                self._drain_member_sync_commands(limit=1)
                self._drain_full_sync_commands(limit=1)
                self._drain_commands()

                self._stop_evt.wait(sleep_ms / 1000.0)

            except Exception:
                logger.exception(f"{self._prefix} unhandled exception in run loop — will retry in 5s")
                try:
                    self._disconnect()
                except Exception:
                    pass
                self._stop_evt.wait(5.0)

        self._disconnect()
        logger.info(f"{self._prefix} stopped")

    # ------------------------------------------------------------------ #
    # Connection management
    # ------------------------------------------------------------------ #

    def _connect_wait_remaining(self, *, now: float | None = None) -> float:
        current = time.monotonic() if now is None else float(now)
        return max(0.0, float(self._next_connect_at_mono or 0.0) - current)

    def _record_connect_failure(self, error: str) -> float:
        self._connect_failures = min(int(self._connect_failures or 0) + 1, 8)
        delay = min(
            self._connect_retry_base_sec * (2 ** max(self._connect_failures - 1, 0)),
            self._connect_retry_max_sec,
        )
        self._next_connect_at_mono = time.monotonic() + float(delay)
        self._last_connect_error = str(error or "connect failed")
        self._last_connect_attempt_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return float(delay)

    def _record_connect_success(self) -> None:
        self._connect_failures = 0
        self._next_connect_at_mono = 0.0
        self._last_connect_error = ""
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._last_connect_attempt_at = now_iso
        self._last_connect_success_at = now_iso

    def defer_reconnect(self, delay_sec: float, *, reason: str = "deferred") -> bool:
        if self._connected:
            return False
        delay = max(0.0, float(delay_sec or 0.0))
        target = time.monotonic() + delay
        if target <= float(self._next_connect_at_mono or 0.0):
            return False
        self._next_connect_at_mono = target
        self._last_connect_error = f"deferred: {str(reason or 'deferred')}"
        return True

    def _connect(self):
        """Connect to device via PullSDK."""
        ip = self._device.get("ipAddress") or self._device.get("ip_address", "")
        port = self._device.get("portNumber") or self._device.get("port_number") or self._device.get("devicePort") or 4370
        self._last_connect_attempt_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        logger.info(
            "%s connect attempt: name=%r ip=%s port=%s failures=%s",
            self._prefix,
            self._device_name,
            ip,
            port,
            self._connect_failures,
        )
        try:
            self._sdk = PullSDKDevice(device_payload=self._device, logger=logger)
            ok = self._sdk.connect()
            if ok:
                self._connected = True
                self._record_connect_success()
                logger.info(f"{self._prefix} connected OK: name={self._device_name!r} ip={ip} port={port}")
            else:
                self._connected = False
                self._sdk = None
                delay = self._record_connect_failure("connect returned False")
                logger.error(
                    f"{self._prefix} connect returned False: "
                    f"name={self._device_name!r} ip={ip} port={port} "
                    f"next_retry_in={delay:.1f}s"
                )
        except Exception as e:
            delay = self._record_connect_failure(str(e))
            logger.error(
                f"{self._prefix} connect FAILED: "
                f"name={self._device_name!r} ip={ip} port={port} error={e} "
                f"next_retry_in={delay:.1f}s"
            )
            self._connected = False
            self._sdk = None

    def _disconnect(self):
        if self._connected or self._sdk:
            logger.debug(f"{self._prefix} disconnect: was_connected={self._connected}")
        if self._sdk:
            try:
                self._sdk.disconnect()
            except Exception as _disc_exc:
                logger.debug(f"{self._prefix} disconnect error (non-fatal): {_disc_exc}")
        self._sdk = None
        self._connected = False

    def pause_for_sync(self, timeout: float = 20.0) -> bool:
        """Ask worker to disconnect and wait until it confirms.

        Called by UltraSyncScheduler before it opens its own TCP connection.
        Returns True if the worker acknowledged the pause within *timeout* seconds.
        """
        self._sync_paused_ack.clear()
        self._sync_pause.set()
        acked = self._sync_paused_ack.wait(timeout=timeout)
        if not acked:
            logger.warning(
                f"{self._prefix} pause_for_sync: worker did not ack within {timeout}s "
                f"(it may still be mid-poll — sync will proceed anyway)"
            )
        return acked

    def resume_from_sync(self):
        """Allow worker to reconnect after sync engine has disconnected."""
        # Mark cache as stale (reset timestamp) but DON'T wipe the data.
        # The stale cache is still valid for immediate TOTP verification —
        # credentials/users rarely change within a single sync cycle.
        # This avoids a blocking 5-second load_local_state() on the first
        # event after resume, which delays the door-open command.
        # The cache will refresh lazily on next TTL expiry (background-safe).
        self._cached_state_ts = 0.0
        self._sync_pause.clear()

    # ------------------------------------------------------------------ #
    # Command queue: door open requests from API/tray, executed inline
    # ------------------------------------------------------------------ #

    def request_door_open(self, door_id: int, pulse_ms: int, timeout: float = 2.0) -> Dict[str, Any]:
        """Thread-safe: enqueue a door-open command, wait for result.

        Called from the HTTP handler thread.  The worker drains the queue
        between polls and executes via its already-connected SDK, avoiding
        the TCP disconnect/reconnect cycle that caused 5s latency.
        """
        result_event = threading.Event()
        result_box: Dict[str, Any] = {"ok": False, "error": "timeout"}
        try:
            self._cmd_queue.put_nowait((door_id, pulse_ms, result_event, result_box))
        except queue.Full:
            return {"ok": False, "error": "command queue full"}

        result_event.wait(timeout=timeout)
        return result_box

    def request_member_sync(self, member_id: int) -> bool:
        normalized_member_id = int(member_id)
        with self._member_sync_lock:
            if normalized_member_id in self._pending_member_sync_ids:
                return False
            self._pending_member_sync_ids.add(normalized_member_id)
            self._pending_member_syncs.append(normalized_member_id)
        return True

    def request_full_sync(self, reason: str = "manual", fingerprint_hash: str | None = None) -> bool:
        normalized_reason = str(reason or "manual").strip() or "manual"
        with self._full_sync_lock:
            if self._pending_full_sync_request is not None:
                return False
            self._pending_full_sync_request = {
                "reason": normalized_reason,
                "fingerprint_hash": str(fingerprint_hash or "").strip() or None,
            }
        return True

    def _drain_commands(self):
        """Execute pending door-open commands using the current SDK connection."""
        while not self._cmd_queue.empty():
            try:
                door_id, pulse_ms, result_event, result_box = self._cmd_queue.get_nowait()
            except queue.Empty:
                break
            try:
                if self._sdk is None or not self._connected:
                    result_box["ok"] = False
                    result_box["error"] = "not connected"
                else:
                    ok = self._sdk.open_door(door_id=door_id, pulse_time_ms=pulse_ms, timeout_ms=4000)
                    result_box["ok"] = bool(ok)
                    result_box["error"] = "" if ok else "open_door returned False"
                    logger.info(
                        f"{self._prefix} CMD door_open: door={door_id} pulse={pulse_ms}ms ok={ok}"
                    )
            except Exception as e:
                result_box["ok"] = False
                result_box["error"] = str(e)
                logger.warning(
                    f"{self._prefix} CMD door_open FAILED: door={door_id} err={e}"
                )
            finally:
                result_event.set()

    def _drain_member_sync_commands(self, limit: int = 1) -> int:
        if limit <= 0:
            return 0

        drained = 0
        while drained < limit:
            with self._member_sync_lock:
                if not self._pending_member_syncs:
                    break
                member_id = int(self._pending_member_syncs.popleft())
                self._pending_member_sync_ids.discard(member_id)

            try:
                if self._sdk is None or not self._connected:
                    self.request_member_sync(member_id)
                    break
                raw_sdk = getattr(self._sdk, "_sdk", None)
                if raw_sdk is None:
                    self.request_member_sync(member_id)
                    break
                from app.core.device_sync import DeviceSyncEngine

                engine = DeviceSyncEngine(cfg=self._cfg or SimpleNamespace(), logger=logger)
                engine.sync_member_on_connected_sdk(
                    sdk=raw_sdk,
                    device=self._device,
                    member_id=member_id,
                    source="ultra_targeted_member_sync",
                )
            except Exception as exc:
                logger.warning(
                    "%s targeted member sync failed: member_id=%s err=%s",
                    self._prefix,
                    member_id,
                    exc,
                )
            drained += 1
        return drained

    def _drain_full_sync_commands(self, limit: int = 1) -> int:
        if limit <= 0:
            return 0

        drained = 0
        while drained < limit:
            with self._full_sync_lock:
                request = self._pending_full_sync_request
                self._pending_full_sync_request = None
            if request is None:
                break
            reason = str(request.get("reason") or "manual")
            fingerprint_hash = str(request.get("fingerprint_hash") or "").strip() or None

            try:
                if self._sdk is None or not self._connected:
                    self.request_full_sync(reason=reason, fingerprint_hash=fingerprint_hash)
                    break
                raw_sdk = getattr(self._sdk, "_sdk", None)
                if raw_sdk is None:
                    self.request_full_sync(reason=reason, fingerprint_hash=fingerprint_hash)
                    break
                cache = load_sync_cache()
                if cache is None:
                    logger.warning("%s full sync skipped: no sync cache available", self._prefix)
                    self._mark_full_sync_finished(
                        reason=reason,
                        ok=False,
                        duration_ms=0.0,
                        error="no sync cache available",
                    )
                    self._notify_full_sync_finished(
                        reason=reason,
                        ok=False,
                        fingerprint_hash=None,
                        duration_ms=0.0,
                        error="no sync cache available",
                    )
                    drained += 1
                    continue

                from app.core.device_sync import DeviceSyncEngine

                device_copy = dict(self._device or {})
                device_copy["accessDataMode"] = "DEVICE"
                filtered_cache_attrs = dict(getattr(cache, "__dict__", {}))
                filtered_cache_attrs["devices"] = [device_copy]
                filtered_cache = SimpleNamespace(**filtered_cache_attrs)
                engine = DeviceSyncEngine(cfg=self._cfg or SimpleNamespace(), logger=logger)
                started_at = time.time()
                started_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at))
                self._mark_full_sync_started(reason=reason, engine=engine, started_at=started_iso)
                self._notify_full_sync_started(reason=reason)
                engine.run_one_device_on_connected_sdk(
                    sdk=raw_sdk,
                    cache=filtered_cache,
                    device=device_copy,
                    source=reason,
                    changed_ids=None,
                )
                duration_ms = max(0.0, (time.time() - started_at) * 1000.0)
                self._mark_full_sync_finished(
                    reason=reason,
                    ok=True,
                    duration_ms=duration_ms,
                    error="",
                )
                self._notify_full_sync_finished(
                    reason=reason,
                    ok=True,
                    fingerprint_hash=fingerprint_hash,
                    duration_ms=duration_ms,
                    error="",
                )
            except Exception as exc:
                logger.warning(
                    "%s full sync failed: reason=%s err=%s",
                    self._prefix,
                    reason,
                    exc,
                )
                self._mark_full_sync_finished(
                    reason=reason,
                    ok=False,
                    duration_ms=0.0,
                    error=str(exc),
                )
                self._notify_full_sync_finished(
                    reason=reason,
                    ok=False,
                    fingerprint_hash=None,
                    duration_ms=0.0,
                    error=str(exc),
                )
            drained += 1
        return drained

    def _mark_full_sync_started(self, *, reason: str, engine: Any, started_at: str) -> None:
        with self._active_sync_lock:
            self._active_sync_engine = engine
            self._current_full_sync_reason = str(reason or "manual")
            self._last_full_sync_started_at = started_at
            self._full_sync_running = True
            self._last_full_sync_error = ""

    def _mark_full_sync_finished(
        self,
        *,
        reason: str,
        ok: bool,
        duration_ms: float,
        error: str,
    ) -> None:
        finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._active_sync_lock:
            self._active_sync_engine = None
            self._current_full_sync_reason = str(reason or "manual")
            self._last_full_sync_finished_at = finished_at
            self._last_full_sync_duration_ms = max(0.0, float(duration_ms or 0.0))
            self._last_full_sync_error = "" if ok else str(error or "sync failed")
            self._full_sync_running = False

    def _notify_full_sync_started(self, *, reason: str) -> None:
        cb = self._on_full_sync_started
        if cb is None:
            return
        try:
            cb(device_id=self._device_id, reason=str(reason or "manual"))
        except Exception:
            logger.debug("%s full sync started callback failed", self._prefix, exc_info=True)

    def _notify_full_sync_finished(
        self,
        *,
        reason: str,
        ok: bool,
        fingerprint_hash: str | None,
        duration_ms: float,
        error: str,
    ) -> None:
        cb = self._on_full_sync_finished
        if cb is None:
            return
        try:
            cb(
                device_id=self._device_id,
                reason=str(reason or "manual"),
                ok=bool(ok),
                fingerprint_hash=str(fingerprint_hash or "").strip() or None,
                duration_ms=max(0.0, float(duration_ms or 0.0)),
                error=str(error or ""),
            )
        except Exception:
            logger.debug("%s full sync finished callback failed", self._prefix, exc_info=True)

    # ------------------------------------------------------------------ #
    # RTLog polling with watchdog (15s timeout)
    # ------------------------------------------------------------------ #

    def _poll_with_watchdog(self) -> Optional[List[Dict[str, Any]]]:
        """Poll RTLog with thread-based watchdog. Returns events or None on timeout."""
        result: List[Optional[List[Dict[str, Any]]]] = [None]
        error: List[Optional[Exception]] = [None]

        def _poll():
            try:
                assert self._sdk is not None
                result[0] = self._sdk.poll_rtlog_once()
            except Exception as e:
                error[0] = e

        t = threading.Thread(target=_poll, daemon=True)
        t0 = time.monotonic()
        t.start()
        t.join(timeout=self._poll_timeout_sec)
        elapsed_ms = (time.monotonic() - t0) * 1000

        # Update EMA
        alpha = 0.2
        self._poll_ema_ms = alpha * elapsed_ms + (1 - alpha) * self._poll_ema_ms

        if t.is_alive():
            logger.error(
                f"{self._prefix} poll_rtlog WATCHDOG TIMEOUT "
                f"(>{self._poll_timeout_sec}s elapsed={elapsed_ms:.0f}ms) — forcing reconnect"
            )
            return None
        if error[0]:
            logger.error(
                f"{self._prefix} poll_rtlog ERROR: {error[0]} "
                f"(elapsed={elapsed_ms:.0f}ms) — forcing reconnect"
            )
            return None
        events = result[0] or []
        if events:
            logger.debug(f"{self._prefix} poll_rtlog OK: {len(events)} event(s) in {elapsed_ms:.0f}ms")
        return events

    # ------------------------------------------------------------------ #
    # Event deduplication
    # ------------------------------------------------------------------ #

    def _pre_populate_seen(self):
        """Load recent event IDs from DB to prevent re-processing after restart."""
        try:
            recent_rows = get_recent_access_history(limit=200)
            for row in recent_rows:
                eid = getattr(row, "event_id", "") or ""
                if eid and eid not in self._seen:
                    self._seen.append(str(eid))
            logger.debug(f"{self._prefix} pre-populated {len(self._seen)} seen event IDs")
        except Exception as e:
            logger.warning(f"{self._prefix} pre_populate_seen failed: {e}")

    def _is_seen(self, event_id: str) -> bool:
        if event_id in self._seen:
            return True
        self._seen.append(event_id)
        return False

    # ------------------------------------------------------------------ #
    # Event classification (core ULTRA logic)
    # ------------------------------------------------------------------ #

    def _process_event(self, evt: Dict[str, Any]):
        """Classify RTLog event and route to appropriate handler."""
        if not hasattr(self, "_card_cooldown") or not isinstance(self._card_cooldown, dict):
            self._card_cooldown = {}
        if not hasattr(self, "_card_cooldown_sec"):
            settings = getattr(self, "_settings", {}) or {}
            anti_fraude_duration = settings.get("anti_fraude_duration")
            if anti_fraude_duration is not None and int(anti_fraude_duration) > 0:
                self._card_cooldown_sec = float(anti_fraude_duration)
            else:
                self._card_cooldown_sec = float(settings.get("replay_block_window_seconds", 0))

        card_no = str(evt.get("cardNo", "") or "").strip()
        event_type_raw = evt.get("eventType", "")
        event_time = str(evt.get("eventTime", "") or "").strip()
        event_id = str(evt.get("eventId", "") or "").strip()
        door_id_raw = evt.get("doorId")
        raw_row = evt.get("rawRow") or {}

        # Build a fallback event_id if not present
        if not event_id:
            event_id = f"{self._device_id}:{event_time}:{card_no}"

        if self._is_seen(event_id):
            logger.debug(f"{self._prefix} SKIP duplicate event_id={event_id}")
            return

        # Card-level cooldown: the C3-400 fires separate events per door for a
        # single card/QR scan. Without this, the turnstile re-opens after the
        # user has already passed through.
        if card_no:
            now_mono = time.monotonic()
            last_seen = self._card_cooldown.get(card_no, 0.0)
            if (now_mono - last_seen) < self._card_cooldown_sec:
                logger.debug(
                    f"{self._prefix} SKIP card cooldown: card={card_no!r} "
                    f"elapsed={now_mono - last_seen:.1f}s < {self._card_cooldown_sec}s"
                )
                return
            self._card_cooldown[card_no] = now_mono
            # Prune old entries to avoid unbounded growth
            if len(self._card_cooldown) > 2000:
                cutoff = now_mono - self._card_cooldown_sec * 2
                self._card_cooldown = {k: v for k, v in self._card_cooldown.items() if v > cutoff}

        self._events_processed += 1

        logger.debug(
            f"{self._prefix} event #{self._events_processed}: "
            f"id={event_id} card={card_no!r} type={event_type_raw!r} time={event_time!r} door={door_id_raw!r}"
        )

        # Parse event type: 0 = normal/verified (ALLOW), anything else = DENY
        try:
            event_type_int = int(event_type_raw)
        except (ValueError, TypeError):
            event_type_int = -1
            logger.warning(
                f"{self._prefix} unrecognised eventType={event_type_raw!r} for event_id={event_id}"
            )

        is_allow = (event_type_int == 0)

        # Parse door_id to int
        door_id: Optional[int] = None
        if door_id_raw is not None:
            try:
                door_id = int(door_id_raw)
            except (ValueError, TypeError):
                pass

        if is_allow:
            self._handle_allow(card_no, event_time, event_id, door_id, str(event_type_raw), raw_row)
        elif self._is_totp_format(card_no):
            self._handle_totp_rescue(card_no, event_time, event_id, door_id, raw_row)
        else:
            self._handle_deny(card_no, event_time, event_id, door_id, str(event_type_raw), raw_row)

    def _is_totp_format(self, code: str) -> bool:
        """Check if scanned code matches TOTP format: prefix + N digits."""
        if not self._settings.get("totp_enabled", True):
            return False
        if not self._settings.get("totp_validation", True):
            return False
        if not self._settings.get("ultra_totp_rescue_enabled", True):
            return False

        prefix = self._settings.get("totp_prefix", "9")
        digits = int(self._settings.get("totp_digits", 7))
        expected_len = len(prefix) + digits

        matched = (
            len(code) == expected_len
            and code.startswith(prefix)
            and code[len(prefix):].isdigit()
        )
        if not matched and len(code) > 0:
            logger.debug(
                f"{self._prefix} TOTP format check MISS: code_len={len(code)} "
                f"expected_len={expected_len} prefix_match={code[:len(prefix)] == prefix} "
                f"code_preview={code[:2]}***{code[-2:] if len(code) > 2 else ''}"
            )
        return matched

    # ------------------------------------------------------------------ #
    # ALLOW handler (passive observation, enrichment only)
    # ------------------------------------------------------------------ #

    def _handle_allow(
        self, card_no: str, event_time: str, event_id: str,
        door_id: Optional[int], event_type: str, raw_row: Dict[str, Any],
    ):
        """Device already opened door. Enrich with user data for popup/history."""
        creds, users_by_am, users_by_card = self._get_cached_local_state()

        # Simple dict lookup -- no validation (device already decided)
        user = None
        hits = users_by_card.get(card_no) or []
        if hits:
            user = hits[0] if isinstance(hits, list) else hits

        # Fallback: for fingerprint scans the device sets cardNo=pin (F-004).
        # If card lookup missed, try users_by_am using the raw RTLog pin field.
        if user is None and raw_row:
            pin_raw = str(raw_row.get("pin") or "").strip()
            if pin_raw.isdigit():
                try:
                    user = users_by_am.get(int(pin_raw))
                except Exception:
                    pass

        user_name = ""
        user_image = ""
        user_membership_id: Optional[int] = None
        user_phone = ""
        user_valid_from = ""
        user_valid_to = ""
        image_source = ""
        user_image_status = ""
        scan_mode = "RFID_CARD"

        if isinstance(user, dict):
            user_name = str(user.get("fullName", user.get("full_name", user.get("name", ""))) or "")
            user_image = str(user.get("image", "") or "")
            raw_am_id = user.get("activeMembershipId")
            if raw_am_id is not None:
                try:
                    user_membership_id = int(str(raw_am_id).strip())
                except (ValueError, TypeError):
                    pass
            user_phone = str(user.get("phone", "") or "")
            user_valid_from = str(user.get("validFrom", user.get("valid_from", "")) or "")
            user_valid_to = str(user.get("validTo", user.get("valid_to", "")) or "")
            image_source = str(user.get("imageSource", "") or "")
            user_image_status = str(user.get("userImageStatus", "") or "")

        if not user_name:
            logger.warning(
                f"{self._prefix} rtlog ALLOW: card={card_no!r} — "
                f"user NOT found in local cache (card not in sync_users)"
            )
        logger.info(
            f"{self._prefix} rtlog ALLOW: card={card_no!r} user={user_name!r} "
            f"door={door_id} event_id={event_id}"
        )

        self._enqueue_notification(
            event_id=event_id,
            allowed=True,
            reason="DEVICE_ALLOWED",
            scan_mode=scan_mode,
            user_full_name=user_name,
            user_image=user_image,
            user_membership_id=user_membership_id,
            user_phone=user_phone,
            user_valid_from=user_valid_from,
            user_valid_to=user_valid_to,
            image_source=image_source,
            user_image_status=user_image_status,
        )
        self._enqueue_history(
            event_id=event_id,
            allowed=True,
            reason="DEVICE_ALLOWED",
            event_type=event_type,
            card_no=card_no,
            event_time=event_time,
            door_id=door_id,
            raw=raw_row,
        )

    # ------------------------------------------------------------------ #
    # TOTP Rescue handler (active: verify + open door)
    # ------------------------------------------------------------------ #

    def _handle_totp_rescue(
        self, code: str, event_time: str, event_id: str,
        door_id: Optional[int], raw_row: Dict[str, Any],
    ):
        """Device denied a TOTP code. Verify locally, open door if valid."""
        creds, users_by_am, users_by_card = self._get_cached_local_state()

        t0 = time.monotonic()
        result = verify_totp(
            scanned=code,
            settings=self._settings,
            creds_payload=creds,
            users_by_am=users_by_am,
            users_by_card=users_by_card,
        )
        decision_ms = (time.monotonic() - t0) * 1000

        allowed = result.get("allowed", False)
        reason = result.get("reason", "DENY_TOTP_FAILED")
        user = result.get("user")
        user_name = ""
        user_image = ""
        user_membership_id: Optional[int] = None
        user_phone = ""
        user_valid_from = ""
        user_valid_to = ""
        image_source = ""
        user_image_status = ""

        if isinstance(user, dict):
            user_name = str(user.get("fullName", user.get("full_name", user.get("name", ""))) or "")
            user_image = str(user.get("image", "") or "")
            raw_am_id = user.get("activeMembershipId")
            if raw_am_id is not None:
                try:
                    user_membership_id = int(str(raw_am_id).strip())
                except (ValueError, TypeError):
                    pass
            user_phone = str(user.get("phone", "") or "")
            user_valid_from = str(user.get("validFrom", user.get("valid_from", "")) or "")
            user_valid_to = str(user.get("validTo", user.get("valid_to", "")) or "")
            image_source = str(user.get("imageSource", "") or "")
            user_image_status = str(user.get("userImageStatus", "") or "")

        cmd_ms = 0.0
        cmd_ok: Optional[bool] = None
        cmd_error = ""

        masked_code = code[0] + "*" * (len(code) - 2) + code[-1] if len(code) > 2 else code
        logger.info(
            f"{self._prefix} TOTP_RESCUE: code={masked_code} "
            f"allowed={allowed} reason={reason} user={user_name!r} "
            f"decision_ms={decision_ms:.1f} event_id={event_id}"
        )

        if allowed:
            # Open door
            logger.info(
                f"{self._prefix} TOTP_RESCUE opening door: door_id={door_id} "
                f"user={user_name!r} code={masked_code}"
            )
            t_cmd = time.monotonic()
            door_opened = self._open_door_with_retry(door_id=door_id)
            cmd_ms = (time.monotonic() - t_cmd) * 1000
            cmd_ok = door_opened

            if door_opened:
                self._totp_rescues += 1
                logger.info(
                    f"{self._prefix} TOTP_RESCUE door OPENED: code={masked_code} "
                    f"user={user_name!r} decision={decision_ms:.0f}ms cmd={cmd_ms:.0f}ms"
                )
            else:
                allowed = False
                reason = "DOOR_CMD_FAILED"
                cmd_error = "door open failed after valid TOTP"
                self._door_cmd_failures += 1
                logger.error(
                    f"{self._prefix} TOTP_RESCUE door FAILED to open: code={masked_code} "
                    f"user={user_name!r} cmd_ms={cmd_ms:.0f}ms door_cmd_failures={self._door_cmd_failures}"
                )
        else:
            self._totp_failures += 1
            logger.info(
                f"{self._prefix} TOTP_RESCUE DENY: code={masked_code} reason={reason} "
                f"user={user_name!r} totp_failures={self._totp_failures}"
            )

        self._enqueue_notification(
            event_id=event_id,
            allowed=allowed,
            reason=reason,
            scan_mode="QR_TOTP",
            user_full_name=user_name,
            user_image=user_image,
            user_membership_id=user_membership_id,
            user_phone=user_phone,
            user_valid_from=user_valid_from,
            user_valid_to=user_valid_to,
            image_source=image_source,
            user_image_status=user_image_status,
        )
        self._enqueue_history(
            event_id=event_id,
            allowed=allowed,
            reason=reason,
            event_type="QR_TOTP",
            card_no=code,
            event_time=event_time,
            door_id=door_id,
            raw=raw_row,
            decision_ms=decision_ms,
            cmd_ms=cmd_ms,
            cmd_ok=cmd_ok,
            cmd_error=cmd_error,
        )

    def _open_door_with_retry(self, *, door_id: Optional[int] = None) -> bool:
        """Open door via PullSDK. Retry once on failure. Returns True if succeeded."""
        resolved_door_id = int(self._settings.get("door_entry_id", 1))
        try:
            candidate = int(door_id) if door_id is not None else 0
            if candidate > 0:
                resolved_door_id = candidate
        except Exception:
            pass

        # Per-door pulse from doorPresets (set in dashboard), fallback to device-level pulseTimeMs.
        pulse_ms = int(self._settings.get("pulse_time_ms", 3000))
        for p in (self._settings.get("door_presets") or []):
            if not isinstance(p, dict):
                continue
            dn = p.get("doorNumber") or p.get("door_number")
            if dn is not None and int(dn) == resolved_door_id:
                ps = p.get("pulseSeconds") or p.get("pulse_seconds")
                if ps is not None and int(ps) > 0:
                    pulse_ms = int(ps) * 1000
                break

        logger.debug(
            f"{self._prefix} open_door_with_retry: resolved_door_id={resolved_door_id} "
            f"pulse_ms={pulse_ms} sdk_connected={bool(self._sdk and self._connected)}"
        )
        for attempt in range(2):
            try:
                if self._sdk is None:
                    logger.error(f"{self._prefix} open_door attempt {attempt + 1}: sdk is None (not connected)")
                    break
                ok = self._sdk.open_door(door_id=resolved_door_id, pulse_time_ms=pulse_ms, timeout_ms=4000)
                if ok:
                    logger.debug(f"{self._prefix} open_door succeeded on attempt {attempt + 1}")
                    return True
                else:
                    logger.warning(
                        f"{self._prefix} open_door attempt {attempt + 1} returned False"
                    )
            except Exception as e:
                logger.warning(
                    f"{self._prefix} open_door attempt {attempt + 1} EXCEPTION: {e}"
                )
            if attempt == 0:
                time.sleep(0.1)
        logger.error(f"{self._prefix} open_door_with_retry: all attempts failed for door_id={resolved_door_id}")
        return False

    # ------------------------------------------------------------------ #
    # DENY handler (passive observation)
    # ------------------------------------------------------------------ #

    def _handle_deny(
        self, card_no: str, event_time: str, event_id: str,
        door_id: Optional[int], event_type: str, raw_row: Dict[str, Any],
    ):
        """Device denied a non-TOTP code. Log and notify."""
        logger.info(
            f"{self._prefix} rtlog DENY: card={card_no!r} reason=DEVICE_DENIED "
            f"event_type={event_type!r} door={door_id} event_id={event_id}"
        )
        self._enqueue_notification(
            event_id=event_id,
            allowed=False,
            reason="DEVICE_DENIED",
            scan_mode="RFID_CARD",
            user_full_name="",
            user_image="",
            user_membership_id=None,
            user_phone="",
            user_valid_from="",
            user_valid_to="",
        )
        self._enqueue_history(
            event_id=event_id,
            allowed=False,
            reason="DEVICE_DENIED",
            event_type=event_type,
            card_no=card_no,
            event_time=event_time,
            door_id=door_id,
            raw=raw_row,
        )

    # ------------------------------------------------------------------ #
    # Notification and history helpers
    # ------------------------------------------------------------------ #

    def _enqueue_notification(
        self,
        *,
        event_id: str,
        allowed: bool,
        reason: str,
        scan_mode: str,
        user_full_name: str,
        user_image: str,
        user_membership_id: Optional[int],
        user_phone: str,
        user_valid_from: str,
        user_valid_to: str,
        image_source: str = "",
        user_image_status: str = "",
    ):
        popup_enabled = self._settings.get("popup_enabled", True)
        if not popup_enabled:
            return

        # User-facing message for error states
        message = ""
        if reason == "DOOR_CMD_FAILED":
            message = "Valid code but door did not open -- try again or use card"

        try:
            req = NotificationRequest(
                event_id=event_id,
                title="Acces",
                message=message,
                image_path="",
                popup_show_image=bool(self._settings.get("popup_show_image", True)),
                user_full_name=user_full_name,
                user_image=user_image,
                user_valid_from=user_valid_from,
                user_valid_to=user_valid_to,
                user_membership_id=user_membership_id,
                user_phone=user_phone,
                device_id=self._device_id,
                device_name=self._device_name,
                allowed=allowed,
                reason=reason,
                scan_mode=scan_mode,
                image_source=image_source,
                user_image_status=user_image_status,
                popup_duration_sec=int(self._settings.get("popup_duration_sec", 3)),
                popup_enabled=True,
                win_notify_enabled=bool(self._settings.get("win_notify_enabled", False)),
            )
            self._popup_q.put_nowait(req)
            logger.debug(
                f"{self._prefix} popup enqueued: allowed={allowed} reason={reason} "
                f"user={user_full_name!r} scan_mode={scan_mode} event_id={event_id}"
            )
        except queue.Full:
            logger.warning(
                f"{self._prefix} popup queue FULL — dropping notification "
                f"(allowed={allowed} user={user_full_name!r} event_id={event_id})"
            )

    def _enqueue_history(
        self,
        *,
        event_id: str,
        allowed: bool,
        reason: str,
        event_type: str,
        card_no: str,
        event_time: str,
        door_id: Optional[int] = None,
        raw: Optional[Dict[str, Any]] = None,
        decision_ms: float = 0.0,
        cmd_ms: float = 0.0,
        cmd_ok: Optional[bool] = None,
        cmd_error: str = "",
    ):
        """Insert history via insert_access_history() (DB-level dedup with INSERT OR IGNORE).

        Only enqueues to the history queue for backend sync if insert succeeds (rowcount=1).
        """
        poll_ms = self._poll_ema_ms

        # Use the existing insert_access_history which does INSERT OR IGNORE
        try:
            rowcount = insert_access_history(
                event_id=event_id,
                device_id=self._device_id,
                door_id=door_id,
                card_no=card_no,
                event_time=event_time,
                event_type=event_type,
                allowed=allowed,
                reason=reason,
                poll_ms=poll_ms,
                decision_ms=decision_ms,
                cmd_ms=cmd_ms,
                cmd_ok=cmd_ok,
                cmd_error=cmd_error,
                raw=raw or {},
                history_source="ULTRA",
            )
            inserted = rowcount == 1
        except Exception as e:
            logger.error(f"{self._prefix} history DB insert failed: {e}")
            inserted = False  # treat as duplicate to avoid bypass of dedup gate

        if not inserted:
            return  # duplicate, already processed

        try:
            rec = HistoryRecord(
                event_id=event_id,
                device_id=self._device_id,
                door_id=door_id,
                card_no=card_no,
                event_time=event_time,
                event_type=event_type,
                allowed=allowed,
                reason=reason,
                poll_ms=poll_ms,
                decision_ms=decision_ms,
                cmd_ms=cmd_ms,
                cmd_ok=cmd_ok is True,
                cmd_error=cmd_error,
                raw=raw or {},
            )
            self._history_q.put_nowait(rec)
        except queue.Full:
            logger.warning(f"{self._prefix} history queue full, dropping record")

    # ------------------------------------------------------------------ #
    # Local state caching (avoid per-event DB reads)
    # ------------------------------------------------------------------ #

    def _get_cached_local_state(self):
        """Return (creds, users_by_am, users_by_card) with TTL-based cache.

        If stale data exists, returns it immediately and reloads in the
        background so the caller (TOTP verification + door command) is never
        blocked by the 3-5 second load_local_state() SQLite query.
        """
        now = time.monotonic()
        needs_refresh = self._cached_state is None or (now - self._cached_state_ts) > self._CACHE_TTL_SEC

        if needs_refresh:
            if self._cached_state is not None:
                # Stale data exists — return immediately, reload in background
                if not getattr(self, "_cache_bg_loading", False):
                    self._cache_bg_loading = True
                    def _bg_load():
                        try:
                            result = load_local_state()
                            if result and isinstance(result, (tuple, list)) and len(result) >= 3:
                                self._cached_state = result
                                self._cached_state_ts = time.monotonic()
                                creds, uam, ucard = result
                                logger.debug(
                                    f"{self._prefix} bg cache refresh done: "
                                    f"creds={len(creds)} users_by_am={len(uam)} users_by_card={len(ucard)}"
                                )
                        except Exception as e:
                            logger.warning(f"{self._prefix} bg cache refresh failed: {e}")
                        finally:
                            self._cache_bg_loading = False
                    threading.Thread(target=_bg_load, daemon=True, name=f"cache-{self._device_id}").start()
                return self._cached_state
            else:
                # No data at all — must load synchronously (first time only)
                logger.debug(f"{self._prefix} refreshing local state cache from DB (sync, first load)")
                result = load_local_state()
                if result is None or not isinstance(result, (tuple, list)) or len(result) < 3:
                    logger.warning(f"{self._prefix} load_local_state() returned invalid data: {type(result)}")
                    self._cached_state = ({}, {}, {})
                else:
                    self._cached_state = result
                self._cached_state_ts = now
                creds, users_by_am, users_by_card = self._cached_state
                logger.debug(
                    f"{self._prefix} local state cache refreshed: "
                    f"creds={len(creds)} users_by_am={len(users_by_am)} users_by_card={len(users_by_card)}"
                )
        return self._cached_state

    # ------------------------------------------------------------------ #
    # Status snapshot
    # ------------------------------------------------------------------ #

    def get_snapshot(self) -> Dict[str, Any]:
        return {
            "device_id": self._device_id,
            "device_name": self._device_name,
            "mode": "ULTRA",
            "rtlog_polling": bool(self._settings.get("ultra_rtlog_enabled", True)),
            "totp_rescue_enabled": bool(self._settings.get("ultra_totp_rescue_enabled", True)),
            "connected": self._connected,
            "events_processed": self._events_processed,
            "totp_rescues": self._totp_rescues,
            "totp_failures": self._totp_failures,
            "door_cmd_failures": self._door_cmd_failures,
            "poll_ema_ms": round(self._poll_ema_ms, 1),
            "connect_failures": int(self._connect_failures or 0),
            "connect_retry_wait_ms": round(self._connect_wait_remaining() * 1000.0, 1),
            "last_connect_error": self._last_connect_error,
            "last_connect_attempt_at": self._last_connect_attempt_at,
            "last_connect_success_at": self._last_connect_success_at,
            "full_sync_running": self._full_sync_running,
            "full_sync_reason": self._current_full_sync_reason,
            "last_full_sync_started_at": self._last_full_sync_started_at,
            "last_full_sync_finished_at": self._last_full_sync_finished_at,
            "last_full_sync_duration_ms": round(self._last_full_sync_duration_ms, 1),
            "last_full_sync_error": self._last_full_sync_error,
        }

    def get_progress_snapshot(self) -> tuple[Optional[Dict[str, Any]], int]:
        with self._active_sync_lock:
            engine = self._active_sync_engine
        if engine and hasattr(engine, "get_progress_snapshot"):
            try:
                return engine.get_progress_snapshot()
            except Exception:
                return None, 0
        return None, 0


# ---------------------------------------------------------------------------
# UltraSyncScheduler
# ---------------------------------------------------------------------------

class UltraSyncScheduler:
    """Periodically pushes user data to ULTRA-mode devices using DeviceSyncEngine logic."""

    def __init__(self, cfg: Any, logger_inst: logging.Logger):
        self._cfg = cfg
        self._logger = logger_inst
        self._stop = threading.Event()
        self._wake_sync = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._devices: List[Dict[str, Any]] = []
        self._last_hash: Dict[int, str] = {}  # device_id -> payload hash
        self._last_sync_at: Dict[int, str] = {}
        self._next_sync_at: Dict[int, str] = {}
        self._workers: Dict[int, "UltraDeviceWorker"] = {}
        self._active_sync_lock = threading.Lock()
        self._active_sync_engine: Optional[Any] = None
        self._pending_sync_lock = threading.Lock()
        self._pending_sync_requested = False
        self._pending_full_sync = False
        self._pending_changed_ids: Set[int] = set()
        self._pending_all_devices = False
        self._pending_device_ids: Set[int] = set()
        self._pending_reason = "manual"

    def set_workers(self, workers: Dict[int, "UltraDeviceWorker"]):
        """Register per-device worker references so sync requests stay worker-owned."""
        self._workers = workers

    def _handle_worker_full_sync_started(self, *, device_id: int, reason: str) -> None:
        self._logger.info(
            "[ULTRA:%s] full sync started on live worker: reason=%s",
            device_id,
            str(reason or "manual"),
        )

    def _handle_worker_full_sync_finished(
        self,
        *,
        device_id: int,
        reason: str,
        ok: bool,
        fingerprint_hash: str | None,
        duration_ms: float,
        error: str,
    ) -> None:
        if ok and fingerprint_hash:
            self._last_hash[int(device_id)] = str(fingerprint_hash)
            self._last_sync_at[int(device_id)] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if ok:
            self._logger.info(
                "[ULTRA:%s] full sync finished on live worker in %.0fms: reason=%s",
                device_id,
                max(0.0, float(duration_ms or 0.0)),
                str(reason or "manual"),
            )
            return
        self._logger.warning(
            "[ULTRA:%s] full sync failed on live worker: reason=%s err=%s",
            device_id,
            str(reason or "manual"),
            str(error or "sync failed"),
        )

    def force_resync(self, device_id: int):
        """F-015: Clear in-memory hash for a device to force re-push on next cycle."""
        self._last_hash.pop(device_id, None)
        self._logger.info("[UltraSyncScheduler] force_resync: cleared hash for device_id=%s", device_id)

    def start(self, devices: List[Dict[str, Any]]):
        self._devices = devices
        self._stop.clear()
        self._wake_sync.clear()
        self._logger.info(
            "[UltraSyncScheduler] starting: %d device(s), ids=%s",
            len(devices), [d.get("id") for d in devices],
        )
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="UltraSyncScheduler"
        )
        self._thread.start()

    def stop(self):
        self._logger.info("[UltraSyncScheduler] stopping")
        self._stop.set()
        self._wake_sync.set()
        if self._thread:
            self._thread.join(timeout=10)
        self._logger.info("[UltraSyncScheduler] stopped")

    def request_sync_now(
        self,
        *,
        changed_ids: set[int] | None = None,
        device_ids: set[int] | None = None,
        reason: str = "manual",
    ) -> None:
        normalized_reason = str(reason or "manual").strip().lower() or "manual"
        normalized_changed_ids = (
            None if changed_ids is None else {
                int(member_id)
                for member_id in changed_ids
                if member_id is not None
            }
        )
        normalized_device_ids = (
            None if device_ids is None else {
                int(device_id)
                for device_id in device_ids
                if device_id is not None
            }
        )
        if normalized_changed_ids is not None and not normalized_changed_ids:
            self._logger.info(
                "[UltraSyncScheduler] request_sync_now skipped: reason=%s changed_ids=0",
                normalized_reason,
            )
            return
        with self._pending_sync_lock:
            self._pending_sync_requested = True
            self._pending_reason = normalized_reason
            if normalized_changed_ids is None:
                self._pending_full_sync = True
                self._pending_changed_ids.clear()
            elif not self._pending_full_sync:
                self._pending_changed_ids.update(normalized_changed_ids)
            if normalized_device_ids is None:
                self._pending_all_devices = True
                self._pending_device_ids.clear()
            elif not self._pending_all_devices:
                self._pending_device_ids.update(normalized_device_ids)
        self._logger.info(
            "[UltraSyncScheduler] request_sync_now: reason=%s changed_ids=%s device_ids=%s",
            normalized_reason,
            "all" if normalized_changed_ids is None else len(normalized_changed_ids),
            "all" if normalized_device_ids is None else len(normalized_device_ids),
        )
        self._wake_sync.set()

    def _drain_pending_sync_request(self) -> tuple[set[int] | None, set[int] | None, str] | None:
        with self._pending_sync_lock:
            if not self._pending_sync_requested:
                return None
            reason = self._pending_reason
            changed_ids = None if self._pending_full_sync else set(self._pending_changed_ids)
            device_ids = None if self._pending_all_devices else set(self._pending_device_ids)
            self._pending_sync_requested = False
            self._pending_full_sync = False
            self._pending_changed_ids.clear()
            self._pending_all_devices = False
            self._pending_device_ids.clear()
            self._pending_reason = "manual"
            return changed_ids, device_ids, reason

    def _run(self):
        """Sync loop: push data to each ULTRA device on its configured interval."""
        # Immediate first sync
        self._sync_all(reason="startup")

        while not self._stop.is_set():
            # Find the shortest interval among all ULTRA devices
            min_interval = 15 * 60  # default 15 min
            for d in self._devices:
                settings = d.get("_settings", {})
                interval = int(settings.get("ultra_sync_interval_minutes", 15)) * 60
                min_interval = min(min_interval, interval)

            woke_for_sync = self._wake_sync.wait(min_interval)
            if self._stop.is_set():
                break
            if woke_for_sync:
                self._wake_sync.clear()
                pending = self._drain_pending_sync_request()
                if pending is None:
                    continue
                changed_ids, device_ids, reason = pending
                self._sync_all(changed_ids=changed_ids, device_ids=device_ids, reason=reason)
                continue
            self._sync_all(reason="timer")

    def _check_worker_health(self):
        """Deprecated: worker restarts are handled exclusively by the watchdog thread.
        Kept as no-op for backward compat in case external code calls it."""
        pass

    def _sync_all(
        self,
        *,
        changed_ids: set[int] | None = None,
        device_ids: set[int] | None = None,
        reason: str = "timer",
    ):
        """Push user data to all ULTRA devices (with hash-based skip)."""
        devices = self._devices if device_ids is None else [
            device for device in self._devices
            if device.get("id") is not None and int(device.get("id")) in device_ids
        ]
        self._logger.info(
            "[UltraSyncScheduler] _sync_all: starting cycle for %d device(s) reason=%s changed_ids=%s device_ids=%s",
            len(devices),
            reason,
            "all" if changed_ids is None else len(changed_ids),
            "all" if device_ids is None else len(device_ids),
        )
        t0 = time.time()
        # Check worker health before each sync cycle
        try:
            self._check_worker_health()
        except Exception as e:
            self._logger.warning("[ULTRA] _check_worker_health error: %s", e)
        synced = 0
        skipped = 0
        failed = 0
        for d in devices:
            device_id = d.get("id")
            try:
                routed = False
                did_sync = False
                worker = self._workers.get(int(device_id)) if device_id is not None else None
                if worker and changed_ids:
                    for member_id in sorted(changed_ids):
                        if worker.request_member_sync(int(member_id)):
                            routed = True
                elif worker and changed_ids is None:
                    from app.core.device_sync import DeviceSyncEngine

                    cache = load_sync_cache()
                    if cache is None:
                        self._logger.warning("[ULTRA:%s] sync skip: no sync cache available", device_id)
                        did_sync = False
                    else:
                        users = getattr(cache, "users", []) or []
                        engine = DeviceSyncEngine(cfg=self._cfg, logger=self._logger)
                        current_hash, desired_users = engine.build_device_sync_fingerprint(
                            device=d,
                            users=list(users),
                        )
                        if self._last_hash.get(device_id) == current_hash:
                            self._logger.info(
                                "[ULTRA:%s] sync skip: fingerprint unchanged (desired_users=%d hash=%s)",
                                device_id,
                                desired_users,
                                current_hash[:12],
                            )
                            did_sync = False
                        else:
                            routed = bool(
                                worker.request_full_sync(
                                    reason=reason,
                                    fingerprint_hash=current_hash,
                                )
                            )
                            if routed:
                                self._logger.info(
                                    "[ULTRA:%s] queued live-worker full sync: desired_users=%d prev_hash=%s new_hash=%s reason=%s",
                                    device_id,
                                    desired_users,
                                    (self._last_hash.get(device_id) or "none")[:12],
                                    current_hash[:12],
                                    str(reason or "manual"),
                                )
                            did_sync = routed
                else:
                    did_sync = self._sync_device(d, changed_ids=changed_ids)
                interval = int(
                    d.get("_settings", {}).get("ultra_sync_interval_minutes", 15)
                ) * 60
                next_t = time.time() + interval
                self._next_sync_at[device_id] = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(next_t)
                )
                if did_sync:
                    self._last_sync_at[device_id] = time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                    )
                    synced += 1
                elif routed:
                    synced += 1
                else:
                    skipped += 1
            except Exception as e:
                failed += 1
                self._logger.error("[ULTRA:%s] sync failed: %s", device_id, e)
        elapsed = time.time() - t0
        self._logger.info(
            "[UltraSyncScheduler] _sync_all: cycle done in %.1fs — synced=%d skipped=%d failed=%d reason=%s",
            elapsed, synced, skipped, failed, reason,
        )

    def _sync_device(
        self,
        device: Dict[str, Any],
        *,
        changed_ids: set[int] | None = None,
    ) -> bool:
        """Push data to a single device with hash-based change detection.

        Reuses DeviceSyncEngine by temporarily treating this ULTRA device
        as a DEVICE-mode device for the push operation.
        """
        from app.core.device_sync import DeviceSyncEngine

        device_id = device.get("id")
        cache = load_sync_cache()
        if cache is None:
            self._logger.warning("[ULTRA:%s] sync skip: no sync cache available", device_id)
            return False

        users = getattr(cache, "users", []) or []
        engine = DeviceSyncEngine(cfg=self._cfg, logger=self._logger)
        current_hash, desired_users = engine.build_device_sync_fingerprint(
            device=device,
            users=list(users),
        )

        if self._last_hash.get(device_id) == current_hash:
            self._logger.info(
                "[ULTRA:%s] sync skip: fingerprint unchanged (desired_users=%d hash=%s)",
                device_id, desired_users, current_hash[:12],
            )
            return False

        self._logger.info(
            "[ULTRA:%s] sync push started: desired_users=%d prev_hash=%s new_hash=%s",
            device_id, desired_users,
            (self._last_hash.get(device_id) or "none")[:12], current_hash[:12],
        )

        device_copy = dict(device or {})
        device_copy["accessDataMode"] = "DEVICE"
        filtered_cache_attrs = dict(getattr(cache, "__dict__", {}))
        filtered_cache_attrs["users"] = list(users)
        filtered_cache_attrs["devices"] = [device_copy]
        filtered_cache = SimpleNamespace(**filtered_cache_attrs)

        # Pause the RTLog worker so it releases the single TCP connection to this device
        worker = self._workers.get(int(device_id)) if device_id is not None else None
        if worker:
            self._logger.info(
                "[ULTRA:%s] sync: pausing RTLog worker for TCP handoff", device_id
            )
            acked = worker.pause_for_sync(timeout=20.0)
            self._logger.info(
                "[ULTRA:%s] sync: worker pause acked=%s — connecting for sync", device_id, acked
            )
        else:
            self._logger.warning(
                "[ULTRA:%s] sync: no worker found — proceeding without pause "
                "(risk: dual TCP connection on C3-200)", device_id
            )

        try:
            with self._active_sync_lock:
                self._active_sync_engine = engine
            did_run = engine.run_one_device_blocking(
                cache=filtered_cache,
                device=device_copy,
                source="ultra_sync",
                changed_ids=changed_ids,
            )
            if not did_run:
                self._logger.warning("[ULTRA:%s] sync push failed or was skipped", device_id)
                return False
            self._last_hash[device_id] = current_hash
            self._logger.info("[ULTRA:%s] sync push complete", device_id)
            return True
        finally:
            with self._active_sync_lock:
                if self._active_sync_engine is engine:
                    self._active_sync_engine = None
            if worker:
                worker.resume_from_sync()
                self._logger.info(
                    "[ULTRA:%s] sync: worker resumed - will reconnect for RTLog polling", device_id
                )

    def get_sync_status(self) -> Dict[int, Dict[str, Any]]:
        return {
            did: {
                "last_sync_at": self._last_sync_at.get(did, ""),
                "next_sync_at": self._next_sync_at.get(did, ""),
            }
            for did in [d.get("id") for d in self._devices]
        }

    def get_active_progress_snapshot(self) -> tuple[Optional[Dict[str, Any]], int]:
        for worker in list(self._workers.values()):
            if hasattr(worker, "get_progress_snapshot"):
                progress, seq = worker.get_progress_snapshot()
                if progress and bool(progress.get("running")):
                    return progress, seq
        with self._active_sync_lock:
            engine = self._active_sync_engine
        if engine and hasattr(engine, "get_progress_snapshot"):
            try:
                return engine.get_progress_snapshot()
            except Exception:
                return None, 0
        return None, 0


# ---------------------------------------------------------------------------
# UltraEngine (orchestrator)
# ---------------------------------------------------------------------------

class UltraEngine:
    """Orchestrates ULTRA mode: sync scheduler + per-device RTLog workers."""

    def __init__(self, cfg: Any, logger_inst: logging.Logger):
        self._cfg = cfg
        self._logger = logger_inst
        self._workers: Dict[int, UltraDeviceWorker] = {}
        self._sync_scheduler: Optional[UltraSyncScheduler] = None
        self._stop_event = threading.Event()
        # M-001: Queue sizes read from backend settings (consistent with AGENT mode).
        from app.core.settings_reader import get_backend_global_settings
        _g = get_backend_global_settings() or {}
        self._popup_q: "queue.Queue[NotificationRequest]" = queue.Queue(
            maxsize=int(_g.get("popup_queue_max", _g.get("notification_queue_max", 5000)))
        )
        self._history_q: "queue.Queue[HistoryRecord]" = queue.Queue(
            maxsize=int(_g.get("history_queue_max", 5000))
        )
        popup_replay_size = max(
            16,
            min(
                int(_g.get("popup_queue_max", _g.get("notification_queue_max", 5000)) or 5000),
                1000,
            ),
        )
        self._popup_capture_lock = threading.Lock()
        self._popup_events_lock = threading.Lock()
        self._popup_events_seq = 0
        self._popup_events_replay: Deque[tuple[int, Dict[str, Any]]] = deque(maxlen=popup_replay_size)
        self._running = False
        self._watchdog_thread: Optional[threading.Thread] = None
        # How often the watchdog checks worker liveness (seconds).
        # Short interval for fast recovery of dead workers.
        self._watchdog_interval_sec: float = 10.0
        # Lock to prevent concurrent worker replacement by watchdog / other threads.
        self._worker_restart_lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._running

    @property
    def popup_q(self) -> "queue.Queue[NotificationRequest]":
        return self._popup_q

    @property
    def history_q(self) -> "queue.Queue[HistoryRecord]":
        return self._history_q

    def capture_popup_events(self, limit: int = 50) -> int:
        drained = 0
        target = max(1, int(limit or 1))
        from app.core.realtime_agent import _popup_payload_from_request

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
        target = max(1, int(limit or 1))
        self.capture_popup_events(limit=max(target * 2, 10))
        with self._popup_events_lock:
            rows = [
                (event_seq, dict(payload))
                for event_seq, payload in self._popup_events_replay
                if int(event_seq) > int(seq)
            ]
        return rows[:target]

    def start(self, devices: List[Dict[str, Any]]):
        """Start ULTRA engine for the given devices."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()

        def _adm(d):
            return str(d.get("accessDataMode") or d.get("access_data_mode") or "").strip().upper()

        ultra_devices = [d for d in devices if _adm(d) == "ULTRA"]

        all_device_count = len(devices)
        non_ultra = [d for d in devices if _adm(d) != "ULTRA"]
        self._logger.info(
            "[ULTRA] start: total_devices=%d ultra_devices=%d skipped=%d",
            all_device_count, len(ultra_devices), len(non_ultra),
        )
        for d in non_ultra:
            self._logger.info(
                "[ULTRA] device id=%s name=%r skipped (accessDataMode=%r / access_data_mode=%r)",
                d.get("id"), d.get("name"), d.get("accessDataMode"), d.get("access_data_mode"),
            )

        if not ultra_devices:
            self._logger.info("[ULTRA] No ULTRA-mode devices found — engine not starting")
            self._running = False
            return

        self._logger.info("[ULTRA] Starting with %d device(s)", len(ultra_devices))

        # TOTP diagnostic: log credential count and system time at startup
        try:
            from app.core.db import list_sync_gym_access_credentials
            creds = list_sync_gym_access_credentials()
            enabled_with_secret = sum(
                1 for c in creds if isinstance(c, dict)
                and c.get("enabled") and (c.get("secretHex") or c.get("secret_hex", "")).strip()
            )
            self._logger.info(
                "[ULTRA] TOTP credentials: total=%d enabled_with_secret=%d system_time=%d",
                len(creds), enabled_with_secret, int(time.time()),
            )
            if enabled_with_secret == 0:
                self._logger.warning(
                    "[ULTRA] WARNING: No enabled TOTP credentials with valid secretHex — "
                    "TOTP rescue will NEVER work until credentials are synced!"
                )
        except Exception as _e:
            self._logger.warning("[ULTRA] Could not check TOTP credentials: %s", _e)

        from app.core.settings_reader import normalize_device_settings

        prepared_devices: List[tuple[Dict[str, Any], Dict[str, Any]]] = []
        for d in ultra_devices:
            settings = normalize_device_settings(d)
            d["_settings"] = settings
            prepared_devices.append((d, settings))
            self._logger.info(
                "[ULTRA] device id=%s name=%r ip=%s port=%s totp_rescue=%s rtlog=%s",
                d.get("id"), d.get("name"),
                d.get("ipAddress", "?"), d.get("portNumber", "?"),
                settings.get("ultra_totp_rescue_enabled", True),
                settings.get("ultra_rtlog_enabled", True),
            )

        self._sync_scheduler = UltraSyncScheduler(self._cfg, self._logger)

        # Start per-device workers first so scheduler can route work to them
        for d, settings in prepared_devices:
            device_id = int(d.get("id", 0))

            worker = UltraDeviceWorker(
                device=d,
                settings=settings,
                popup_q=self._popup_q,
                history_q=self._history_q,
                stop_event=self._stop_event,
                cfg=self._cfg,
                on_full_sync_started=self._sync_scheduler._handle_worker_full_sync_started,
                on_full_sync_finished=self._sync_scheduler._handle_worker_full_sync_finished,
            )
            self._workers[device_id] = worker
            try:
                worker.start()
                self._logger.info("[ULTRA] Worker thread started for device id=%s name=%r", device_id, d.get("name"))
            except Exception as _w_exc:
                self._logger.error("[ULTRA] Worker thread start FAILED for device id=%s: %s", device_id, _w_exc)

        # Start sync scheduler with worker references so it can route timed work
        self._sync_scheduler.set_workers(self._workers)
        self._sync_scheduler.start([d for d, _settings in prepared_devices])

        # Start the watchdog — monitors worker liveness every 30 s, independent
        # of the sync interval, so a crashed worker is restarted promptly.
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            daemon=True,
            name="UltraWatchdog",
        )
        self._watchdog_thread.start()

    def _watchdog_loop(self):
        """Restart dead UltraDeviceWorker threads every _watchdog_interval_sec seconds.

        This is the SOLE restart mechanism.  UltraSyncScheduler._check_worker_health
        is now a no-op — all restarts go through this watchdog to avoid race conditions.
        """
        self._logger.info("[ULTRA] Watchdog started (interval=%.0fs)", self._watchdog_interval_sec)
        while not self._stop_event.wait(self._watchdog_interval_sec):
            for device_id, worker in list(self._workers.items()):
                if worker.is_alive():
                    continue
                with self._worker_restart_lock:
                    # Double-check inside lock: another thread may have restarted it
                    current = self._workers.get(device_id)
                    if current is not None and current.is_alive():
                        continue
                    self._logger.error(
                        "[ULTRA:%s] watchdog: worker thread is dead — restarting", device_id
                    )
                    try:
                        new_worker = UltraDeviceWorker(
                            device=worker._device,
                            settings=worker._settings,
                            popup_q=self._popup_q,
                            history_q=self._history_q,
                            stop_event=self._stop_event,
                            cfg=self._cfg,
                            on_full_sync_started=(
                                self._sync_scheduler._handle_worker_full_sync_started
                                if self._sync_scheduler
                                else None
                            ),
                            on_full_sync_finished=(
                                self._sync_scheduler._handle_worker_full_sync_finished
                                if self._sync_scheduler
                                else None
                            ),
                        )
                        new_worker.start()
                        self._workers[device_id] = new_worker
                        self._logger.info("[ULTRA:%s] watchdog: worker restarted OK", device_id)
                    except Exception as exc:
                        self._logger.error(
                            "[ULTRA:%s] watchdog: worker restart FAILED: %s", device_id, exc
                        )
        self._logger.info("[ULTRA] Watchdog stopped")

    def stop(self):
        """Stop all workers and sync scheduler."""
        if not self._running:
            return
        self._logger.info("[ULTRA] Stopping engine")
        self._stop_event.set()

        # Stop sync scheduler
        if self._sync_scheduler:
            self._sync_scheduler.stop()

        # Stop watchdog (stop_event already set; just wait for it to exit)
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=5)

        # Stop workers
        for device_id, worker in self._workers.items():
            worker.join(timeout=10)
            if worker.is_alive():
                self._logger.warning("[ULTRA:%s] worker did not stop in time", device_id)

        self._workers.clear()
        self._running = False
        self._logger.info("[ULTRA] Engine stopped")

    def get_status(self) -> Dict[str, Any]:
        """Return full ULTRA engine status for /api/v2/ultra/status."""
        devices: Dict[str, Any] = {}
        sync_status = self._sync_scheduler.get_sync_status() if self._sync_scheduler else {}

        for device_id, worker in self._workers.items():
            snap = worker.get_snapshot()
            ss = sync_status.get(device_id, {})
            snap["last_sync_at"] = ss.get("last_sync_at", "")
            snap["next_sync_at"] = ss.get("next_sync_at", "")
            snap["sync_interval_minutes"] = int(
                worker._settings.get("ultra_sync_interval_minutes", 15)
            )
            devices[str(device_id)] = snap

        return {
            "running": self._running,
            "devices": devices,
        }

    def get_sync_progress_snapshot(self) -> tuple[Optional[Dict[str, Any]], int]:
        if not self._sync_scheduler:
            return None, 0
        return self._sync_scheduler.get_active_progress_snapshot()

    def reset_fast_patch_caches(self) -> None:
        for worker in list(getattr(self, "_workers", {}).values()):
            try:
                if hasattr(worker, "reset_fast_patch_caches"):
                    worker.reset_fast_patch_caches()
            except Exception:
                self._logger.warning("[ULTRA] failed to reset worker cache", exc_info=True)

    def defer_reconnects(self, *, duration_sec: float, reason: str = "sync") -> int:
        deferred = 0
        for worker in list(getattr(self, "_workers", {}).values()):
            try:
                if hasattr(worker, "defer_reconnect") and worker.defer_reconnect(duration_sec, reason=str(reason or "sync")):
                    deferred += 1
            except Exception:
                self._logger.debug("[ULTRA] failed to defer worker reconnect", exc_info=True)
        if deferred > 0:
            self._logger.info(
                "[ULTRA] deferred reconnects: workers=%d duration_sec=%.1f reason=%s",
                deferred,
                float(duration_sec or 0.0),
                str(reason or "sync"),
            )
        return deferred

    def request_sync_now(
        self,
        *,
        changed_ids: set[int] | None = None,
        device_ids: set[int] | None = None,
        reason: str = "manual",
    ) -> bool:
        if not self._running or not self._sync_scheduler:
            return False
        normalized_changed_ids = (
            None
            if changed_ids is None
            else {
                int(member_id)
                for member_id in changed_ids
                if member_id is not None
            }
        )
        normalized_device_ids = (
            set(self._workers.keys())
            if device_ids is None
            else {
                int(device_id)
                for device_id in device_ids
                if device_id is not None
            }
        )
        if normalized_changed_ids is not None and not normalized_changed_ids:
            self._logger.info(
                "[ULTRA] skip sync request: empty changed_ids reason=%s",
                str(reason or "manual"),
            )
            return False
        if normalized_changed_ids:
            matched_workers = [
                (device_id, worker)
                for device_id, worker in sorted(self._workers.items())
                if int(device_id) in normalized_device_ids
            ]
            if matched_workers:
                for _device_id, worker in matched_workers:
                    for member_id in sorted(normalized_changed_ids):
                        if hasattr(worker, "request_member_sync"):
                            worker.request_member_sync(int(member_id))
                self._logger.info(
                    "[ULTRA] routed targeted member sync to live workers: devices=%d members=%d reason=%s",
                    len(matched_workers),
                    len(normalized_changed_ids),
                    str(reason or "manual"),
                )
                return True
        if normalized_changed_ids is None:
            routed_device_ids: set[int] = set()
            for device_id, worker in sorted(self._workers.items()):
                if int(device_id) not in normalized_device_ids:
                    continue
                if hasattr(worker, "request_full_sync") and worker.request_full_sync(reason=reason):
                    routed_device_ids.add(int(device_id))
            if routed_device_ids:
                self._logger.info(
                    "[ULTRA] routed full refresh to live workers: devices=%d reason=%s",
                    len(routed_device_ids),
                    str(reason or "manual"),
                )
                remaining_device_ids = set(normalized_device_ids) - routed_device_ids
                if not remaining_device_ids:
                    return True
                normalized_device_ids = remaining_device_ids
        self._sync_scheduler.request_sync_now(
            changed_ids=normalized_changed_ids,
            device_ids=normalized_device_ids,
            reason=reason,
        )
        return True

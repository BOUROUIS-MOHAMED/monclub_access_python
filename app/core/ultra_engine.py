"""ULTRA mode engine: device-firmware RFID/FP + PC-side RTLog observer + TOTP rescue."""

import hashlib
import json
import logging
import queue
import threading
import time
from collections import deque
from types import SimpleNamespace
from typing import Any, Deque, Dict, List, Optional

from app.core.access_types import HistoryRecord, NotificationRequest
from app.core.access_verification import load_local_state, verify_totp
from app.core.db import get_recent_access_history, insert_access_history, load_sync_cache
from app.sdk.pullsdk import PullSDKDevice

logger = logging.getLogger(__name__)


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
    ):
        super().__init__(daemon=True, name=f"UltraWorker-{device.get('id')}")
        self._device = device
        self._settings = settings
        self._popup_q = popup_q
        self._history_q = history_q
        self._stop = stop_event
        self._device_id = int(device.get("id", 0))
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

        # Local state cache (avoid per-event DB reads)
        self._cached_state: Optional[tuple] = None
        self._cached_state_ts: float = 0.0
        self._CACHE_TTL_SEC: float = 5.0

    # ------------------------------------------------------------------ #
    # Main loop
    # ------------------------------------------------------------------ #

    def run(self):
        """Main loop: connect -> poll RTLog -> classify -> repeat."""
        logger.info(f"{self._prefix} started")
        self._pre_populate_seen()

        while not self._stop.is_set():
            # Yield the TCP connection to UltraSyncScheduler when requested
            if self._sync_pause.is_set():
                if self._connected:
                    logger.info(
                        f"{self._prefix} sync pause requested — disconnecting for TCP handoff"
                    )
                    self._disconnect()
                self._sync_paused_ack.set()
                while self._sync_pause.is_set() and not self._stop.is_set():
                    self._stop.wait(0.5)
                self._sync_paused_ack.clear()
                logger.info(f"{self._prefix} sync pause ended — will reconnect")
                continue

            # Connect if needed
            if not self._connected:
                self._connect()
                if not self._connected:
                    self._stop.wait(5.0)
                    continue

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

            self._stop.wait(sleep_ms / 1000.0)

        self._disconnect()
        logger.info(f"{self._prefix} stopped")

    # ------------------------------------------------------------------ #
    # Connection management
    # ------------------------------------------------------------------ #

    def _connect(self):
        """Connect to device via PullSDK."""
        ip = self._device.get("ipAddress") or self._device.get("ip_address", "")
        port = self._device.get("portNumber") or self._device.get("port_number") or self._device.get("devicePort") or 4370
        logger.info(f"{self._prefix} connect attempt: name={self._device_name!r} ip={ip} port={port}")
        try:
            self._sdk = PullSDKDevice(device_payload=self._device, logger=logger)
            ok = self._sdk.connect()
            if ok:
                self._connected = True
                logger.info(f"{self._prefix} connected OK: name={self._device_name!r} ip={ip} port={port}")
            else:
                self._connected = False
                self._sdk = None
                logger.error(
                    f"{self._prefix} connect returned False: "
                    f"name={self._device_name!r} ip={ip} port={port}"
                )
        except Exception as e:
            logger.error(
                f"{self._prefix} connect FAILED: "
                f"name={self._device_name!r} ip={ip} port={port} error={e}"
            )
            self._connected = False
            self._sdk = None

    def _disconnect(self):
        if self._connected or self._sdk:
            logger.debug(f"{self._prefix} disconnect: was_connected={self._connected}")
        if self._sdk:
            try:
                self._sdk.disconnect()
            except Exception:
                pass
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
        self._sync_pause.clear()

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
        if not self._settings.get("ultra_totp_rescue_enabled", True):
            return False

        prefix = self._settings.get("totp_prefix", "9")
        digits = int(self._settings.get("totp_digits", 7))
        expected_len = len(prefix) + digits

        return (
            len(code) == expected_len
            and code.startswith(prefix)
            and code[len(prefix):].isdigit()
        )

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
        pulse_ms = int(self._settings.get("pulse_time_ms", 3000))
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
        """Return (creds, users_by_am, users_by_card) with 5-second cache."""
        now = time.monotonic()
        if self._cached_state is None or (now - self._cached_state_ts) > self._CACHE_TTL_SEC:
            logger.debug(f"{self._prefix} refreshing local state cache from DB")
            self._cached_state = load_local_state()
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
        }


# ---------------------------------------------------------------------------
# UltraSyncScheduler
# ---------------------------------------------------------------------------

class UltraSyncScheduler:
    """Periodically pushes user data to ULTRA-mode devices using DeviceSyncEngine logic."""

    def __init__(self, cfg: Any, logger_inst: logging.Logger):
        self._cfg = cfg
        self._logger = logger_inst
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._devices: List[Dict[str, Any]] = []
        self._last_hash: Dict[int, str] = {}  # device_id -> payload hash
        self._last_sync_at: Dict[int, str] = {}
        self._next_sync_at: Dict[int, str] = {}
        self._workers: Dict[int, "UltraDeviceWorker"] = {}

    def set_workers(self, workers: Dict[int, "UltraDeviceWorker"]):
        """Register per-device worker references so _sync_device can pause them."""
        self._workers = workers

    def start(self, devices: List[Dict[str, Any]]):
        self._devices = devices
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="UltraSyncScheduler"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _run(self):
        """Sync loop: push data to each ULTRA device on its configured interval."""
        # Immediate first sync
        self._sync_all()

        while not self._stop.is_set():
            # Find the shortest interval among all ULTRA devices
            min_interval = 15 * 60  # default 15 min
            for d in self._devices:
                settings = d.get("_settings", {})
                interval = int(settings.get("ultra_sync_interval_minutes", 15)) * 60
                min_interval = min(min_interval, interval)

            self._stop.wait(min_interval)
            if not self._stop.is_set():
                self._sync_all()

    def _sync_all(self):
        """Push user data to all ULTRA devices (with hash-based skip)."""
        for d in self._devices:
            device_id = d.get("id")
            try:
                self._sync_device(d)
                self._last_sync_at[device_id] = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                )
                interval = int(
                    d.get("_settings", {}).get("ultra_sync_interval_minutes", 15)
                ) * 60
                next_t = time.time() + interval
                self._next_sync_at[device_id] = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(next_t)
                )
            except Exception as e:
                self._logger.error("[ULTRA:%s] sync failed: %s", device_id, e)

    def _sync_device(self, device: Dict[str, Any]):
        """Push data to a single device with hash-based change detection.

        Reuses DeviceSyncEngine by temporarily treating this ULTRA device
        as a DEVICE-mode device for the push operation.
        """
        from app.core.device_sync import DeviceSyncEngine

        device_id = device.get("id")
        cache = load_sync_cache()
        if cache is None:
            self._logger.warning("[ULTRA:%s] sync skip: no sync cache available", device_id)
            return

        # Compute hash of current user payload for this device
        users = getattr(cache, "users", []) or []
        # M-004: Include card numbers and fingerprint hashes in payload hash,
        # not just activeMembershipId. Otherwise card-only changes are missed.
        payload_str = json.dumps(
            sorted([
                (
                    u.get("activeMembershipId", ""),
                    u.get("firstCardId", ""),
                    u.get("secondCardId", ""),
                    u.get("fingerprintsHash", ""),
                )
                for u in users if u
            ]),
            sort_keys=True,
        )
        current_hash = hashlib.sha256(payload_str.encode()).hexdigest()

        if self._last_hash.get(device_id) == current_hash:
            self._logger.info("[ULTRA:%s] sync skip: hash unchanged", device_id)
            return

        self._logger.info("[ULTRA:%s] sync push started", device_id)

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
            engine = DeviceSyncEngine(cfg=self._cfg, logger=self._logger)
            engine.run_blocking(cache=filtered_cache, source="ultra_sync")
            self._last_hash[device_id] = current_hash
            self._logger.info("[ULTRA:%s] sync push complete", device_id)
        finally:
            if worker:
                worker.resume_from_sync()
                self._logger.info(
                    "[ULTRA:%s] sync: worker resumed — will reconnect for RTLog polling", device_id
                )

    def get_sync_status(self) -> Dict[int, Dict[str, Any]]:
        return {
            did: {
                "last_sync_at": self._last_sync_at.get(did, ""),
                "next_sync_at": self._next_sync_at.get(did, ""),
            }
            for did in [d.get("id") for d in self._devices]
        }


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
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    @property
    def popup_q(self) -> "queue.Queue[NotificationRequest]":
        return self._popup_q

    @property
    def history_q(self) -> "queue.Queue[HistoryRecord]":
        return self._history_q

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

        # Start per-device workers first so scheduler can reference them
        for d, settings in prepared_devices:
            device_id = int(d.get("id", 0))

            worker = UltraDeviceWorker(
                device=d,
                settings=settings,
                popup_q=self._popup_q,
                history_q=self._history_q,
                stop_event=self._stop_event,
            )
            self._workers[device_id] = worker
            try:
                worker.start()
                self._logger.info("[ULTRA] Worker thread started for device id=%s name=%r", device_id, d.get("name"))
            except Exception as _w_exc:
                self._logger.error("[ULTRA] Worker thread start FAILED for device id=%s: %s", device_id, _w_exc)

        # Start sync scheduler with worker references so it can pause them for TCP handoff
        self._sync_scheduler = UltraSyncScheduler(self._cfg, self._logger)
        self._sync_scheduler.set_workers(self._workers)
        self._sync_scheduler.start([d for d, _settings in prepared_devices])

    def stop(self):
        """Stop all workers and sync scheduler."""
        if not self._running:
            return
        self._logger.info("[ULTRA] Stopping engine")
        self._stop_event.set()

        # Stop sync scheduler
        if self._sync_scheduler:
            self._sync_scheduler.stop()

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

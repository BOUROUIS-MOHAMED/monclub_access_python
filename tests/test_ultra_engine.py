"""Comprehensive tests for UltraDeviceWorker (ultra_engine.py)."""

import queue
import threading
import time
from collections import deque
from types import SimpleNamespace
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch, call

import pytest

from app.core.ultra_engine import UltraDeviceWorker
from app.core.access_types import HistoryRecord, NotificationRequest


# ---------------------------------------------------------------------------
# Helpers / Factories
# ---------------------------------------------------------------------------

def _make_device(device_id: int = 1, name: str = "TestDevice") -> Dict[str, Any]:
    return {
        "id": device_id,
        "name": name,
        "ipAddress": "192.168.1.100",
        "portNumber": 4370,
    }


def _make_settings(**overrides) -> Dict[str, Any]:
    base = {
        "totp_enabled": True,
        "ultra_totp_rescue_enabled": True,
        "totp_prefix": "9",
        "totp_digits": 7,
        "popup_enabled": True,
        "popup_show_image": True,
        "popup_duration_sec": 3,
        "win_notify_enabled": False,
        "door_entry_id": 1,
        "pulse_time_ms": 3000,
        "busy_sleep_min_ms": 0,
        "busy_sleep_max_ms": 50,
        "empty_sleep_min_ms": 200,
        "empty_sleep_max_ms": 500,
        "empty_backoff_factor": 1.35,
        "empty_backoff_max_ms": 2000,
    }
    base.update(overrides)
    return base


def _make_worker(
    device: Optional[Dict[str, Any]] = None,
    settings: Optional[Dict[str, Any]] = None,
    popup_q: Optional[queue.Queue] = None,
    history_q: Optional[queue.Queue] = None,
    stop_event: Optional[threading.Event] = None,
) -> UltraDeviceWorker:
    """Create a UltraDeviceWorker without starting its thread."""
    if device is None:
        device = _make_device()
    if settings is None:
        settings = _make_settings()
    if popup_q is None:
        popup_q = queue.Queue(maxsize=100)
    if history_q is None:
        history_q = queue.Queue(maxsize=100)
    if stop_event is None:
        stop_event = threading.Event()

    # Use __new__ to avoid calling super().__init__ (Thread.__init__)
    # which would register a thread we don't want to start.
    worker = UltraDeviceWorker.__new__(UltraDeviceWorker)

    # Replicate what __init__ does, without calling Thread.__init__
    worker._device = device
    worker._settings = settings
    worker._popup_q = popup_q
    worker._history_q = history_q
    worker._cfg = None
    worker._on_full_sync_started = None
    worker._on_full_sync_finished = None
    worker._stop = stop_event
    worker._stop_evt = stop_event
    worker._device_id = int(device.get("id", 0))
    worker._device_name = str(device.get("name", ""))
    worker._sdk = None
    worker._seen = deque(maxlen=10_000)
    worker._connected = False
    worker._events_processed = 0
    worker._totp_rescues = 0
    worker._totp_failures = 0
    worker._door_cmd_failures = 0
    worker._poll_ema_ms = 0.0
    worker._prefix = f"[ULTRA:{worker._device_id}]"
    worker._card_cooldown = {}
    worker._card_cooldown_sec = float(settings.get("replay_block_window_seconds", 0))

    worker._busy_min = int(settings.get("busy_sleep_min_ms", 0))
    worker._busy_max = int(settings.get("busy_sleep_max_ms", 50))
    worker._empty_min = int(settings.get("empty_sleep_min_ms", 200))
    worker._empty_max = int(settings.get("empty_sleep_max_ms", 500))
    worker._backoff = float(settings.get("empty_backoff_factor", 1.35))
    worker._backoff_cap = int(settings.get("empty_backoff_max_ms", 2000))
    worker._empty_sleep_ms = float(worker._empty_min)
    worker._poll_timeout_sec = 15.0

    worker._cached_state = None
    worker._cached_state_ts = 0.0
    worker._CACHE_TTL_SEC = 5.0
    worker._member_sync_lock = threading.Lock()
    worker._pending_member_syncs = deque()
    worker._pending_member_sync_ids = set()
    worker._full_sync_lock = threading.Lock()
    worker._pending_full_sync_request = None
    worker._active_sync_lock = threading.Lock()
    worker._active_sync_engine = None
    worker._current_full_sync_reason = ""
    worker._last_full_sync_started_at = ""
    worker._last_full_sync_finished_at = ""
    worker._last_full_sync_duration_ms = 0.0
    worker._last_full_sync_error = ""
    worker._full_sync_running = False
    worker._cmd_queue = queue.Queue(maxsize=10)
    worker._wake_evt = threading.Event()
    worker._sync_pause = threading.Event()
    worker._sync_paused_ack = threading.Event()
    worker._connect_retry_base_sec = float(settings.get("connect_retry_base_sec", 2.0))
    worker._connect_retry_max_sec = float(settings.get("connect_retry_max_sec", 15.0))
    worker._connect_failures = 0
    worker._next_connect_at_mono = 0.0
    worker._last_connect_error = ""
    worker._last_connect_attempt_at = ""
    worker._last_connect_success_at = ""
    worker._connect_down_since_mono = 0.0
    worker._connect_down_since_iso = ""
    worker._last_down_error_log_mono = 0.0
    worker._down_error_log_interval_sec = 300.0

    return worker


def _make_event(
    *,
    event_id: str = "evt-001",
    card_no: str = "123456",
    event_type: Any = 0,
    event_time: str = "2024-01-01T12:00:00",
    door_id: Any = 1,
    raw_row: Optional[Dict] = None,
) -> Dict[str, Any]:
    return {
        "eventId": event_id,
        "cardNo": card_no,
        "eventType": event_type,
        "eventTime": event_time,
        "doorId": door_id,
        "rawRow": raw_row or {},
    }


# Minimal local state: (creds, users_by_am, users_by_card)
_EMPTY_LOCAL_STATE = ([], {}, {})

_RFC_SECRET_HEX = "3132333435363738393031323334353637383930"
_RFC_SECRET = bytes.fromhex(_RFC_SECRET_HEX)


def _current_totp_code(prefix: str = "9", digits: int = 7, period: int = 30) -> str:
    """Generate the current TOTP code using the RFC test secret."""
    import struct, hashlib, hmac
    ctr = int(time.time()) // period
    msg = struct.pack(">Q", ctr)
    digest = hmac.new(_RFC_SECRET, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    code = str(code_int % (10 ** digits)).zfill(digits)
    return prefix + code


# ---------------------------------------------------------------------------
# TestIsTotpFormat
# ---------------------------------------------------------------------------

class TestIsTotpFormat:
    """Tests for UltraDeviceWorker._is_totp_format()."""

    def _worker(self, **setting_overrides) -> UltraDeviceWorker:
        return _make_worker(settings=_make_settings(**setting_overrides))

    # --- valid format ---

    def test_valid_default_prefix_7_digits(self):
        # prefix="9", digits=7 => code is "9" + 7 digits = 8 chars
        worker = self._worker()
        assert worker._is_totp_format("91234567") is True

    def test_valid_all_zeros_suffix(self):
        worker = self._worker()
        assert worker._is_totp_format("90000000") is True

    def test_valid_custom_prefix(self):
        worker = self._worker(totp_prefix="7", totp_digits=6)
        assert worker._is_totp_format("7123456") is True

    def test_valid_6_digits(self):
        worker = self._worker(totp_prefix="9", totp_digits=6)
        assert worker._is_totp_format("9123456") is True

    def test_valid_10_digits(self):
        worker = self._worker(totp_prefix="9", totp_digits=10)
        assert worker._is_totp_format("91234567890") is True

    # --- invalid format ---

    def test_wrong_length_too_short(self):
        worker = self._worker()
        # Expected 8 chars (prefix "9" + 7 digits), give 7 chars
        assert worker._is_totp_format("9123456") is False

    def test_wrong_length_too_long(self):
        worker = self._worker()
        assert worker._is_totp_format("912345678") is False

    def test_wrong_prefix(self):
        worker = self._worker(totp_prefix="9", totp_digits=7)
        # correct length but starts with "8" instead of "9"
        assert worker._is_totp_format("81234567") is False

    def test_non_digit_suffix(self):
        worker = self._worker()
        # "9" + 6 digits + 1 letter = 8 chars but suffix not all digits
        assert worker._is_totp_format("9123456A") is False

    def test_empty_string(self):
        worker = self._worker()
        assert worker._is_totp_format("") is False

    def test_pure_digits_no_prefix(self):
        # 8 digits but doesn't start with "9"
        worker = self._worker()
        assert worker._is_totp_format("12345678") is False

    # --- feature flags ---

    def test_totp_disabled_returns_false(self):
        worker = self._worker(totp_enabled=False)
        # Even though format is correct, if totp disabled → False
        assert worker._is_totp_format("91234567") is False

    def test_totp_validation_disabled_returns_false(self):
        worker = self._worker(totp_validation=False)
        assert worker._is_totp_format("91234567") is False

    def test_ultra_totp_rescue_disabled_returns_false(self):
        worker = self._worker(ultra_totp_rescue_enabled=False)
        assert worker._is_totp_format("91234567") is False

    def test_both_flags_disabled_returns_false(self):
        worker = self._worker(totp_enabled=False, ultra_totp_rescue_enabled=False)
        assert worker._is_totp_format("91234567") is False

    def test_totp_enabled_rescue_enabled_valid_code(self):
        # Both enabled and valid format → True
        worker = self._worker(totp_enabled=True, ultra_totp_rescue_enabled=True)
        assert worker._is_totp_format("91234567") is True


# ---------------------------------------------------------------------------
# TestIsSeenDedup
# ---------------------------------------------------------------------------

class TestIsSeenDedup:
    """Tests for UltraDeviceWorker._is_seen()."""

    def test_new_event_id_returns_false_and_adds(self):
        worker = _make_worker()
        result = worker._is_seen("evt-new-001")
        assert result is False
        assert "evt-new-001" in worker._seen

    def test_same_event_id_second_call_returns_true(self):
        worker = _make_worker()
        worker._is_seen("evt-dup-001")
        result = worker._is_seen("evt-dup-001")
        assert result is True

    def test_different_event_ids_both_new(self):
        worker = _make_worker()
        assert worker._is_seen("evt-A") is False
        assert worker._is_seen("evt-B") is False

    def test_seen_deque_grows_with_unique_ids(self):
        worker = _make_worker()
        for i in range(10):
            worker._is_seen(f"evt-{i}")
        assert len(worker._seen) == 10

    def test_duplicate_does_not_grow_deque(self):
        worker = _make_worker()
        worker._is_seen("evt-X")
        worker._is_seen("evt-X")
        assert len(worker._seen) == 1

    def test_prepopulated_ids_are_seen(self):
        worker = _make_worker()
        worker._seen.append("evt-pre-001")
        assert worker._is_seen("evt-pre-001") is True

    def test_empty_string_id(self):
        worker = _make_worker()
        # Empty string can be added without error
        assert worker._is_seen("") is False
        assert worker._is_seen("") is True


# ---------------------------------------------------------------------------
# TestOpenDoorWithRetry
# ---------------------------------------------------------------------------

class TestOpenDoorWithRetry:
    """Tests for UltraDeviceWorker._open_door_with_retry()."""

    def test_success_first_attempt(self):
        worker = _make_worker()
        mock_sdk = MagicMock()
        mock_sdk.open_door.return_value = True
        worker._sdk = mock_sdk

        result = worker._open_door_with_retry()

        assert result is True
        mock_sdk.open_door.assert_called_once_with(
            door_id=1, pulse_time_ms=3000, timeout_ms=4000
        )

    def test_success_on_second_attempt(self):
        worker = _make_worker()
        mock_sdk = MagicMock()
        # First attempt returns False, second returns True
        mock_sdk.open_door.side_effect = [False, True]
        worker._sdk = mock_sdk

        with patch("time.sleep"):  # Skip real sleep(0.1)
            result = worker._open_door_with_retry()

        assert result is True
        assert mock_sdk.open_door.call_count == 2

    def test_failure_both_attempts(self):
        worker = _make_worker()
        mock_sdk = MagicMock()
        mock_sdk.open_door.return_value = False
        worker._sdk = mock_sdk

        with patch("time.sleep"):
            result = worker._open_door_with_retry()

        assert result is False
        assert mock_sdk.open_door.call_count == 2

    def test_exception_on_first_attempt_succeeds_on_second(self):
        worker = _make_worker()
        mock_sdk = MagicMock()
        mock_sdk.open_door.side_effect = [RuntimeError("timeout"), True]
        worker._sdk = mock_sdk

        with patch("time.sleep"):
            result = worker._open_door_with_retry()

        assert result is True
        assert mock_sdk.open_door.call_count == 2

    def test_exception_on_both_attempts(self):
        worker = _make_worker()
        mock_sdk = MagicMock()
        mock_sdk.open_door.side_effect = RuntimeError("connection lost")
        worker._sdk = mock_sdk

        with patch("time.sleep"):
            result = worker._open_door_with_retry()

        assert result is False
        assert mock_sdk.open_door.call_count == 2

    def test_uses_door_entry_id_from_settings(self):
        worker = _make_worker(settings=_make_settings(door_entry_id=3))
        mock_sdk = MagicMock()
        mock_sdk.open_door.return_value = True
        worker._sdk = mock_sdk

        worker._open_door_with_retry()

        mock_sdk.open_door.assert_called_once_with(
            door_id=3, pulse_time_ms=3000, timeout_ms=4000
        )

    def test_uses_pulse_time_from_settings(self):
        worker = _make_worker(settings=_make_settings(pulse_time_ms=5000))
        mock_sdk = MagicMock()
        mock_sdk.open_door.return_value = True
        worker._sdk = mock_sdk

        worker._open_door_with_retry()

        mock_sdk.open_door.assert_called_once_with(
            door_id=1, pulse_time_ms=5000, timeout_ms=4000
        )

    def test_exactly_two_attempts_max(self):
        """Only retry once (2 total attempts)."""
        worker = _make_worker()
        mock_sdk = MagicMock()
        mock_sdk.open_door.return_value = False
        worker._sdk = mock_sdk

        with patch("time.sleep"):
            worker._open_door_with_retry()

        # range(2) => attempts 0 and 1 only
        assert mock_sdk.open_door.call_count == 2


def test_request_door_open_wakes_idle_worker() -> None:
    stop_event = threading.Event()
    worker = UltraDeviceWorker(
        device=_make_device(),
        settings=_make_settings(
            empty_sleep_min_ms=2000,
            empty_sleep_max_ms=2000,
            empty_backoff_max_ms=2000,
        ),
        popup_q=queue.Queue(maxsize=10),
        history_q=queue.Queue(maxsize=10),
        stop_event=stop_event,
    )
    worker._pre_populate_seen = MagicMock()
    worker._get_cached_local_state = MagicMock()
    worker._connected = True
    worker._sdk = MagicMock()
    worker._sdk.open_door.return_value = True
    worker._poll_with_watchdog = MagicMock(return_value=[])
    worker_wait_started = threading.Event()
    original_wait_for_work = worker._wait_for_work

    def _observing_wait_for_work(timeout_sec: float) -> None:
        worker_wait_started.set()
        original_wait_for_work(timeout_sec)

    worker._wait_for_work = _observing_wait_for_work

    worker.start()
    try:
        assert worker_wait_started.wait(timeout=1.0)

        result = worker.request_door_open(door_id=2, pulse_ms=1500, timeout=0.5)

        assert result == {"ok": True, "error": ""}
        worker._sdk.open_door.assert_called_once_with(
            door_id=2,
            pulse_time_ms=1500,
            timeout_ms=4000,
        )
    finally:
        stop_event.set()
        worker.join(timeout=1.0)


# ---------------------------------------------------------------------------
# TestProcessEventRouting — ALLOW path
# ---------------------------------------------------------------------------

class TestProcessEventAllow:
    """Tests for ALLOW event routing via _process_event()."""

    def _patched_worker(self, **setting_overrides):
        worker = _make_worker(settings=_make_settings(**setting_overrides))
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()
        return worker

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_allow_event_puts_notification_on_popup_q(self, mock_lls, mock_iah):
        worker = self._patched_worker()
        evt = _make_event(event_type=0, card_no="111111")

        worker._process_event(evt)

        assert not worker._popup_q.empty()
        req = worker._popup_q.get_nowait()
        assert isinstance(req, NotificationRequest)
        assert req.allowed is True
        assert req.reason == "DEVICE_ALLOWED"

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_allow_event_puts_record_on_history_q(self, mock_lls, mock_iah):
        worker = self._patched_worker()
        evt = _make_event(event_type=0, card_no="111111")

        worker._process_event(evt)

        assert not worker._history_q.empty()
        rec = worker._history_q.get_nowait()
        assert isinstance(rec, HistoryRecord)
        assert rec.allowed is True
        assert rec.reason == "DEVICE_ALLOWED"

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_allow_event_increments_events_processed(self, mock_lls, mock_iah):
        worker = self._patched_worker()
        assert worker._events_processed == 0

        worker._process_event(_make_event(event_type=0))

        assert worker._events_processed == 1

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_allow_event_notification_has_correct_device_id(self, mock_lls, mock_iah):
        worker = self._patched_worker()
        worker._process_event(_make_event(event_type=0))

        req = worker._popup_q.get_nowait()
        assert req.device_id == 1

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_allow_event_history_uses_event_id(self, mock_lls, mock_iah):
        worker = self._patched_worker()
        worker._process_event(_make_event(event_id="unique-evt-XYZ", event_type=0))

        rec = worker._history_q.get_nowait()
        assert rec.event_id == "unique-evt-XYZ"

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_allow_event_enriches_user_data(self, mock_lls, mock_iah):
        user = {"fullName": "Alice Smith", "image": "alice.jpg", "activeMembershipId": 99}
        users_by_card = {"111111": [user]}
        local_state = ([], {99: user}, users_by_card)

        worker = _make_worker()
        worker._cached_state = local_state
        worker._cached_state_ts = time.monotonic()

        with patch("app.core.ultra_engine.insert_access_history", return_value=1):
            worker._process_event(_make_event(event_type=0, card_no="111111"))

        req = worker._popup_q.get_nowait()
        assert req.user_full_name == "Alice Smith"
        assert req.user_image == "alice.jpg"
        assert req.user_membership_id == 99

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_allow_event_scan_mode_is_rfid_card(self, mock_lls, mock_iah):
        worker = self._patched_worker()
        worker._process_event(_make_event(event_type=0))

        req = worker._popup_q.get_nowait()
        assert req.scan_mode == "RFID_CARD"


# ---------------------------------------------------------------------------
# TestProcessEventRouting — DENY path
# ---------------------------------------------------------------------------

class TestProcessEventDeny:
    """Tests for DENY event routing via _process_event()."""

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_deny_event_puts_notification_on_popup_q(self, mock_lls, mock_iah):
        worker = _make_worker()
        evt = _make_event(event_type=1, card_no="222222")

        worker._process_event(evt)

        assert not worker._popup_q.empty()
        req = worker._popup_q.get_nowait()
        assert req.allowed is False
        assert req.reason == "DEVICE_DENIED"

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_deny_event_puts_record_on_history_q(self, mock_lls, mock_iah):
        worker = _make_worker()
        evt = _make_event(event_type=5, card_no="222222")

        worker._process_event(evt)

        assert not worker._history_q.empty()
        rec = worker._history_q.get_nowait()
        assert rec.allowed is False
        assert rec.reason == "DEVICE_DENIED"

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_deny_event_increments_events_processed(self, mock_lls, mock_iah):
        worker = _make_worker()
        assert worker._events_processed == 0

        worker._process_event(_make_event(event_type=99))

        assert worker._events_processed == 1

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_deny_event_scan_mode_is_rfid_card(self, mock_lls, mock_iah):
        worker = _make_worker()
        worker._process_event(_make_event(event_type=2))

        req = worker._popup_q.get_nowait()
        assert req.scan_mode == "RFID_CARD"

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_deny_event_no_user_enrichment(self, mock_lls, mock_iah):
        worker = _make_worker()
        worker._process_event(_make_event(event_type=3))

        req = worker._popup_q.get_nowait()
        assert req.user_full_name == ""
        assert req.user_image == ""
        assert req.user_membership_id is None

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_non_zero_event_type_is_deny(self, mock_lls, mock_iah):
        """Any non-zero numeric event type that's not TOTP format → DENY."""
        worker = _make_worker()
        for etype in [1, 2, 255, -1]:
            worker._popup_q = queue.Queue(maxsize=100)
            eid = f"evt-deny-{etype}"
            worker._seen = deque(maxlen=10_000)  # reset dedup
            worker._process_event(_make_event(event_type=etype, event_id=eid))
            req = worker._popup_q.get_nowait()
            assert req.allowed is False


# ---------------------------------------------------------------------------
# TestProcessEventDedup
# ---------------------------------------------------------------------------

class TestProcessEventDedup:
    """Tests for event deduplication in _process_event()."""

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_duplicate_event_id_not_counted(self, mock_lls, mock_iah):
        worker = _make_worker()
        evt = _make_event(event_id="dup-evt-001", event_type=0)

        worker._process_event(evt)
        worker._process_event(evt)  # duplicate

        assert worker._events_processed == 1

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_duplicate_event_only_one_notification(self, mock_lls, mock_iah):
        worker = _make_worker()
        evt = _make_event(event_id="dup-evt-002", event_type=0)

        worker._process_event(evt)
        worker._process_event(evt)

        assert worker._popup_q.qsize() == 1

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_duplicate_event_only_one_history_record(self, mock_lls, mock_iah):
        worker = _make_worker()
        evt = _make_event(event_id="dup-evt-003", event_type=0)

        worker._process_event(evt)
        worker._process_event(evt)

        assert worker._history_q.qsize() == 1

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_unique_events_are_each_processed(self, mock_lls, mock_iah):
        worker = _make_worker()

        for i in range(5):
            worker._process_event(_make_event(event_id=f"unique-{i}", event_type=0))

        assert worker._events_processed == 5
        assert worker._popup_q.qsize() == 5

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_empty_event_id_uses_fallback_key(self, mock_lls, mock_iah):
        worker = _make_worker()
        evt = _make_event(event_id="", event_type=0, card_no="777777")

        worker._process_event(evt)
        worker._process_event(evt)  # same fallback key

        assert worker._events_processed == 1


# ---------------------------------------------------------------------------
# TestTotpRescueFlow
# ---------------------------------------------------------------------------

class TestTotpRescueFlow:
    """Tests for TOTP rescue event routing."""

    def _make_totp_event(self, code: str, event_id: str = "totp-evt-001") -> Dict[str, Any]:
        return _make_event(
            event_id=event_id,
            card_no=code,
            event_type=1,  # Non-zero = device denied it
            door_id=1,
        )

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.verify_totp")
    def test_valid_totp_opens_door_and_allows(self, mock_verify, mock_iah):
        """Valid TOTP + door opens → allowed=True in notification and history."""
        mock_verify.return_value = {
            "allowed": True,
            "reason": "ALLOW",
            "user": {"fullName": "Bob", "activeMembershipId": 42},
        }

        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        mock_sdk = MagicMock()
        mock_sdk.open_door.return_value = True
        worker._sdk = mock_sdk

        code = "91234567"  # valid TOTP format: prefix "9" + 7 digits
        worker._process_event(self._make_totp_event(code))

        # Door should have been opened
        mock_sdk.open_door.assert_called_once()

        # Notification
        assert not worker._popup_q.empty()
        req = worker._popup_q.get_nowait()
        assert req.allowed is True
        assert req.scan_mode == "QR_TOTP"
        assert req.user_full_name == "Bob"

        # History
        assert not worker._history_q.empty()
        rec = worker._history_q.get_nowait()
        assert rec.allowed is True
        assert rec.event_type == "QR_TOTP"

        # Counters
        assert worker._totp_rescues == 1
        assert worker._totp_failures == 0

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.verify_totp")
    def test_invalid_totp_does_not_open_door(self, mock_verify, mock_iah):
        """Invalid TOTP → door never opened, denied notification."""
        mock_verify.return_value = {
            "allowed": False,
            "reason": "DENY_NO_MATCH",
            "user": None,
        }

        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        mock_sdk = MagicMock()
        worker._sdk = mock_sdk

        code = "91234567"
        worker._process_event(self._make_totp_event(code))

        # Door must NOT be opened
        mock_sdk.open_door.assert_not_called()

        req = worker._popup_q.get_nowait()
        assert req.allowed is False
        assert worker._totp_failures == 1
        assert worker._totp_rescues == 0

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.verify_totp")
    def test_valid_totp_door_open_fails_returns_deny(self, mock_verify, mock_iah):
        """Valid TOTP but door open fails → allowed=False, reason=DOOR_CMD_FAILED."""
        mock_verify.return_value = {
            "allowed": True,
            "reason": "ALLOW",
            "user": None,
        }

        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        mock_sdk = MagicMock()
        mock_sdk.open_door.return_value = False
        worker._sdk = mock_sdk

        code = "91234567"
        with patch("time.sleep"):
            worker._process_event(self._make_totp_event(code))

        req = worker._popup_q.get_nowait()
        assert req.allowed is False
        assert req.reason == "DOOR_CMD_FAILED"
        assert "door did not open" in req.message

        rec = worker._history_q.get_nowait()
        assert rec.allowed is False
        assert rec.reason == "DOOR_CMD_FAILED"

        assert worker._door_cmd_failures == 1
        assert worker._totp_rescues == 0

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.verify_totp")
    def test_totp_event_increments_events_processed(self, mock_verify, mock_iah):
        mock_verify.return_value = {"allowed": False, "reason": "DENY_NO_MATCH", "user": None}

        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()
        worker._sdk = MagicMock()

        assert worker._events_processed == 0
        worker._process_event(self._make_totp_event("91234567"))
        assert worker._events_processed == 1

    def test_non_totp_format_code_routes_to_deny_not_totp(self):
        """Code that does not match TOTP format + non-zero event type → DENY path."""
        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        # "12345" doesn't match TOTP format (prefix "9", len 8)
        evt = _make_event(event_type=1, card_no="12345")

        with patch("app.core.ultra_engine.insert_access_history", return_value=1):
            worker._process_event(evt)

        req = worker._popup_q.get_nowait()
        assert req.reason == "DEVICE_DENIED"  # went through deny path, not TOTP


# ---------------------------------------------------------------------------
# TestPopupQueueBehavior
# ---------------------------------------------------------------------------

class TestPopupQueueBehavior:
    """Tests related to popup queue: disabled, full, content."""

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_popup_disabled_no_notification_queued(self, mock_lls, mock_iah):
        worker = _make_worker(settings=_make_settings(popup_enabled=False))
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        worker._process_event(_make_event(event_type=0))

        assert worker._popup_q.empty()

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_popup_still_queues_history_when_disabled(self, mock_lls, mock_iah):
        """Even if popup is disabled, history should still be written."""
        worker = _make_worker(settings=_make_settings(popup_enabled=False))
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        worker._process_event(_make_event(event_type=0))

        # History queue should have the record
        assert not worker._history_q.empty()

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_popup_queue_full_does_not_raise(self, mock_lls, mock_iah):
        """When popup queue is full, worker should log warning and not crash."""
        popup_q = queue.Queue(maxsize=1)
        # Pre-fill the queue
        popup_q.put_nowait(MagicMock())

        worker = _make_worker(popup_q=popup_q)
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        # Should not raise
        worker._process_event(_make_event(event_type=0, event_id="full-queue-test"))

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_notification_event_id_matches_event(self, mock_lls, mock_iah):
        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        worker._process_event(_make_event(event_id="my-special-id", event_type=0))

        req = worker._popup_q.get_nowait()
        assert req.event_id == "my-special-id"

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_notification_device_name_populated(self, mock_lls, mock_iah):
        worker = _make_worker(device=_make_device(name="GymFront"))
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        worker._process_event(_make_event(event_type=0))

        req = worker._popup_q.get_nowait()
        assert req.device_name == "GymFront"


@patch("app.core.settings_reader.get_backend_global_settings", return_value={})
def test_ultra_engine_popup_replay_fans_out_to_multiple_consumers(_mock_settings):
    from app.core.ultra_engine import UltraEngine

    engine = UltraEngine(cfg=SimpleNamespace(), logger_inst=MagicMock())
    req = NotificationRequest(
        event_id="evt-popup-1",
        title="Acces",
        message="ok",
        image_path="",
        popup_show_image=True,
        user_full_name="Mohamed Test",
        user_image="",
        user_valid_from="",
        user_valid_to="",
        user_membership_id=77,
        user_phone="555-0100",
        device_id=5,
        device_name="Front Gate",
        allowed=True,
        reason="DEVICE_ALLOWED",
        scan_mode="RFID_CARD",
        popup_duration_sec=3,
        popup_enabled=True,
        win_notify_enabled=False,
    )

    engine.popup_q.put_nowait(req)

    latest_seq = engine.get_latest_popup_event_seq()
    first_read = engine.get_popup_events_since(0, limit=10)
    second_read = engine.get_popup_events_since(0, limit=10)

    assert latest_seq == 1
    assert first_read == second_read
    assert first_read[0][1]["userFullName"] == "Mohamed Test"


# ---------------------------------------------------------------------------
# TestHistoryQueueBehavior
# ---------------------------------------------------------------------------

class TestHistoryQueueBehavior:
    """Tests related to history queue behavior and DB dedup."""

    @patch("app.core.ultra_engine.insert_access_history", return_value=0)  # rowcount=0 → duplicate
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_db_duplicate_rowcount_zero_skips_history_queue(self, mock_lls, mock_iah):
        """If insert_access_history returns 0 (already exists), don't enqueue."""
        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        worker._process_event(_make_event(event_type=0))

        assert worker._history_q.empty()

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_history_queue_full_does_not_raise(self, mock_lls, mock_iah):
        history_q = queue.Queue(maxsize=1)
        history_q.put_nowait(MagicMock())  # Fill it up

        worker = _make_worker(history_q=history_q)
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        # Should not raise
        worker._process_event(_make_event(event_type=0, event_id="full-history-test"))

    @patch("app.core.ultra_engine.insert_access_history", side_effect=Exception("DB down"))
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_insert_exception_skips_history_enqueue(self, mock_lls, mock_iah):
        """If insert throws, worker sets inserted=False (fail-closed) to prevent dedup bypass."""
        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        worker._process_event(_make_event(event_type=0))

        # On exception, code sets inserted=False (fail-closed) so history is NOT enqueued
        assert worker._history_q.empty()

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_history_record_fields_are_correct(self, mock_lls, mock_iah):
        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        worker._process_event(
            _make_event(
                event_id="hist-field-test",
                card_no="555555",
                event_type=0,
                door_id=2,
                event_time="2024-06-15T10:30:00",
            )
        )

        rec = worker._history_q.get_nowait()
        assert rec.event_id == "hist-field-test"
        assert rec.card_no == "555555"
        assert rec.device_id == 1
        assert rec.door_id == 2
        assert rec.event_time == "2024-06-15T10:30:00"
        assert rec.allowed is True
        assert rec.reason == "DEVICE_ALLOWED"


# ---------------------------------------------------------------------------
# TestGetSnapshot
# ---------------------------------------------------------------------------

class TestGetSnapshot:
    """Tests for UltraDeviceWorker.get_snapshot()."""

    def test_snapshot_has_expected_keys(self):
        worker = _make_worker()
        snap = worker.get_snapshot()

        expected_keys = {
            "device_id", "device_name", "mode", "rtlog_polling",
            "totp_rescue_enabled", "connected", "events_processed",
            "totp_rescues", "totp_failures", "door_cmd_failures",
            "poll_ema_ms",
        }
        assert expected_keys.issubset(snap.keys())

    def test_snapshot_mode_is_ultra(self):
        worker = _make_worker()
        assert worker.get_snapshot()["mode"] == "ULTRA"

    def test_snapshot_initial_counters_zero(self):
        worker = _make_worker()
        snap = worker.get_snapshot()
        assert snap["events_processed"] == 0
        assert snap["totp_rescues"] == 0
        assert snap["totp_failures"] == 0
        assert snap["door_cmd_failures"] == 0
        assert snap["connected"] is False

    def test_snapshot_device_id_matches(self):
        worker = _make_worker(device=_make_device(device_id=42))
        assert worker.get_snapshot()["device_id"] == 42

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_snapshot_events_processed_reflects_actual(self, mock_lls, mock_iah):
        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        for i in range(3):
            worker._process_event(_make_event(event_id=f"snap-{i}", event_type=0))

        snap = worker.get_snapshot()
        assert snap["events_processed"] == 3


# ---------------------------------------------------------------------------
# TestConnectBackoff
# ---------------------------------------------------------------------------

class TestConnectBackoff:
    def test_connect_failure_schedules_retry_backoff(self):
        worker = _make_worker(settings=_make_settings(connect_retry_base_sec=2, connect_retry_max_sec=15))
        fake_sdk = MagicMock()
        fake_sdk.connect.return_value = False

        with (
            patch("app.core.ultra_engine.PullSDKDevice", return_value=fake_sdk),
            patch("app.core.ultra_engine.time.monotonic", return_value=100.0),
        ):
            worker._connect()

        assert worker._connected is False
        assert worker._connect_failures == 1
        assert worker._last_connect_error == "connect returned False"
        assert worker._connect_wait_remaining(now=101.0) == pytest.approx(1.0)

    def test_connect_success_resets_retry_backoff(self):
        worker = _make_worker()
        worker._connect_failures = 3
        worker._next_connect_at_mono = 250.0
        worker._last_connect_error = "previous failure"
        fake_sdk = MagicMock()
        fake_sdk.connect.return_value = True

        with patch("app.core.ultra_engine.PullSDKDevice", return_value=fake_sdk):
            worker._connect()

        assert worker._connected is True
        assert worker._connect_failures == 0
        assert worker._connect_wait_remaining(now=999.0) == 0.0
        assert worker._last_connect_error == ""
        assert worker._last_connect_success_at != ""

    def test_defer_reconnect_extends_retry_window_for_disconnected_worker(self):
        worker = _make_worker()
        worker._connected = False
        worker._next_connect_at_mono = 101.0

        with patch("app.core.ultra_engine.time.monotonic", return_value=100.0):
            changed = worker.defer_reconnect(12.0, reason="sync_write")

        assert changed is True
        assert worker._connect_wait_remaining(now=111.0) == pytest.approx(1.0)
        assert worker._last_connect_error == "deferred: sync_write"

    def test_defer_reconnect_does_not_touch_connected_worker(self):
        worker = _make_worker()
        worker._connected = True
        worker._next_connect_at_mono = 101.0

        with patch("app.core.ultra_engine.time.monotonic", return_value=100.0):
            changed = worker.defer_reconnect(12.0, reason="sync_write")

        assert changed is False
        assert worker._connect_wait_remaining(now=100.5) == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# TestFallbackEventId
# ---------------------------------------------------------------------------

class TestFallbackEventId:
    """Tests for fallback event ID construction when eventId is missing."""

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_missing_event_id_uses_fallback(self, mock_lls, mock_iah):
        """When event has no eventId, a fallback is constructed from device+time+card."""
        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        evt = {
            "eventId": "",
            "cardNo": "888888",
            "eventType": 0,
            "eventTime": "2024-01-01T09:00:00",
            "doorId": 1,
            "rawRow": {},
        }
        worker._process_event(evt)

        # Should have processed (not skipped)
        assert worker._events_processed == 1

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_none_event_id_uses_fallback(self, mock_lls, mock_iah):
        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        evt = {
            "eventId": None,
            "cardNo": "999999",
            "eventType": 0,
            "eventTime": "2024-01-01T09:00:00",
            "doorId": 1,
            "rawRow": {},
        }
        worker._process_event(evt)
        assert worker._events_processed == 1


# ---------------------------------------------------------------------------
# TestDoorIdParsing
# ---------------------------------------------------------------------------

class TestDoorIdParsing:
    """Tests for door_id parsing from event dict."""

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_integer_door_id_preserved(self, mock_lls, mock_iah):
        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        worker._process_event(_make_event(event_type=0, door_id=3))
        rec = worker._history_q.get_nowait()
        assert rec.door_id == 3

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_string_door_id_coerced_to_int(self, mock_lls, mock_iah):
        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        worker._process_event(_make_event(event_type=0, door_id="4"))
        rec = worker._history_q.get_nowait()
        assert rec.door_id == 4

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_none_door_id_stays_none(self, mock_lls, mock_iah):
        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        worker._process_event(_make_event(event_type=0, door_id=None))
        rec = worker._history_q.get_nowait()
        assert rec.door_id is None

    @patch("app.core.ultra_engine.insert_access_history", return_value=1)
    @patch("app.core.ultra_engine.load_local_state", return_value=_EMPTY_LOCAL_STATE)
    def test_invalid_door_id_becomes_none(self, mock_lls, mock_iah):
        worker = _make_worker()
        worker._cached_state = _EMPTY_LOCAL_STATE
        worker._cached_state_ts = time.monotonic()

        worker._process_event(_make_event(event_type=0, door_id="not-a-number"))
        rec = worker._history_q.get_nowait()
        assert rec.door_id is None


class TestPollWithWatchdogNoThreadLeak:
    """Regression: when the inner SDK call hangs, _poll_with_watchdog must not
    orphan a new thread on every call. Each orphan accumulates against the
    Windows process thread limit and eventually causes the whole app to freeze
    overnight (every Thread().start() raises RuntimeError)."""

    def test_skips_poll_when_previous_watchdog_thread_still_alive(self):
        worker = _make_worker()
        worker._poll_timeout_sec = 0.05

        # Simulate an orphan from a previous call that never finished.
        hang = threading.Event()
        prev = threading.Thread(target=hang.wait, daemon=True)
        prev.start()
        worker._watchdog_thread = prev

        before = threading.active_count()
        try:
            result = worker._poll_with_watchdog()
        finally:
            hang.set()
            prev.join(timeout=2.0)

        after = threading.active_count()

        assert result is None, "must signal failure so caller forces reconnect"
        # No new thread should have been spawned while the old one was hung.
        assert after <= before, (
            f"watchdog leaked a thread (before={before} after={after}); "
            "fix preserves bounded thread count under SDK hangs"
        )

    def test_clears_watchdog_reference_after_clean_completion(self):
        worker = _make_worker()
        worker._poll_timeout_sec = 1.0

        sdk = MagicMock()
        sdk.poll_rtlog_once.return_value = []
        worker._sdk = sdk

        result = worker._poll_with_watchdog()

        assert result == []
        # Reference cleared so the next cycle is free to spawn a fresh thread.
        assert getattr(worker, "_watchdog_thread", None) is None

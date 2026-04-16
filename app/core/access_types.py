# app/core/access_types.py
"""Shared dataclasses used by both AGENT and ULTRA realtime engines."""

from dataclasses import dataclass
from typing import Any, Dict, Optional


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
    queued_at: float = 0.0  # perf_counter ms when event was put in queue


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
    user_birthday: str = ""
    image_source: str = ""
    user_image_status: str = ""
    user_profile_image: str = ""
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

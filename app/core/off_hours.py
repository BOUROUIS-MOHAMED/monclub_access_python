"""Weekly plan closures. All clock and persistence inputs are supplied by callers."""
from __future__ import annotations

from dataclasses import dataclass
import json
from math import isfinite

LEAD_MINUTES = 5
DAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")


@dataclass(frozen=True)
class OffWindow:
    day: int
    start: int
    duration: int


def parse_windows(raw) -> tuple[OffWindow, ...]:
    if not isinstance(raw, list):
        return ()
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        day, start, duration = (item.get(k) for k in ("day", "startMinute", "durationMinutes"))
        if (day not in DAYS or type(start) is not int or type(duration) is not int
                or not 0 <= start < 1440 or not 15 <= duration <= 1425
                or start % 15 or duration % 15):
            continue
        out.append(OffWindow(DAYS.index(day), start, duration))
        if len(out) == 7:
            break
    return tuple(out)


def encode_windows(ws) -> str | None:
    return json.dumps([{"day": DAYS[w.day], "startMinute": w.start,
                        "durationMinutes": w.duration} for w in ws]) if ws else None


def decode_windows(text) -> tuple[OffWindow, ...]:
    try:
        return parse_windows(json.loads(text))
    except (TypeError, ValueError):
        return ()


def local_week_minute(epoch: float, utc_offset_sec: int) -> tuple[int, int]:
    days, sec = divmod(int(epoch) + int(utc_offset_sec), 86400)
    return (days + 3) % 7, sec // 60


def _covers(ws, weekday, minute, lead):
    for w in ws:
        dur = w.duration - lead
        if dur <= 0:
            continue
        if w.day == weekday and w.start <= minute < w.start + dur:
            return True
        if w.day == (weekday + 6) % 7 and w.start + dur > 1440 and minute < w.start + dur - 1440:
            return True
    return False


def held(ws, weekday, minute) -> bool:
    return _covers(ws, weekday, minute, LEAD_MINUTES)


def closed(ws, weekday, minute) -> bool:
    return _covers(ws, weekday, minute, 0)


@dataclass(frozen=True)
class OffHoursPlan:
    active: bool
    target: frozenset[int]
    newly_held: frozenset[int]
    released: frozenset[int]
    retry: frozenset[int]


def plan_off_hours(*, now_epoch, utc_offset_sec, trusted, clock_suspect,
                   windows_by_am, known_ids, intent_ids) -> OffHoursPlan:
    intent = frozenset(intent_ids)
    target = frozenset()
    active = bool(trusted and not clock_suspect and utc_offset_sec is not None)
    try:
        if active:
            if not isfinite(float(now_epoch)):
                raise ValueError("non-finite clock")
            day, minute = local_week_minute(now_epoch, utc_offset_sec)
            known = set(known_ids)
            target = frozenset(am for am, ws in windows_by_am.items()
                               if am in known and ws and held(ws, day, minute))
    except Exception:
        active = False
        target = frozenset()
    return OffHoursPlan(active, target, target - intent, intent - target, target & intent)


def held_pins_for_device(device) -> set[str]:
    """Exact known held pins, excluding any pin still used by a live membership."""
    try:
        from app.core import db
        from app.core.device_sync import derive_member_pin, device_pin_scheme
        rows = db.list_off_hours_held_rows()
        if not rows:
            return set()
        scheme = device_pin_scheme(device)
        pins = {derive_member_pin(r, scheme)[0] for r in rows}
        live = live_pins_for_device(device, db.list_sync_users())
        return {p for p in pins - live if p and p.isdigit()}
    except Exception:
        return set()


def live_pins_for_device(device, rows):
    from app.core.device_sync import derive_member_pin, device_pin_scheme
    # Same plan eligibility and pin derivation as _filter_users_for_device.
    allowed = {int(x) for x in (device.get("allowedMemberships") or [])}
    scheme = device_pin_scheme(device)
    return {derive_member_pin(r, scheme)[0] for r in rows
            if not allowed or (r.get("membershipId") is not None and int(r["membershipId"]) in allowed)}


def split_removals(pins, held_pins):
    unplanned, planned = [], []
    for pin in pins:
        (planned if pin in held_pins else unplanned).append(pin)
    return unplanned, planned

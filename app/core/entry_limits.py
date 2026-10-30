"""Pure entry-limit rule shared with the backend; naive gym-local dates and times."""
from __future__ import annotations

from calendar import monthrange
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from typing import Iterable, Mapping

LEAD_MINUTES = 5


@dataclass(frozen=True)
class EntryLimits:
    total: int | None = None
    per_day: int | None = None
    per_week_days: int | None = None
    per_month: int | None = None
    visit_minutes: int = 180


def parse_limits(raw) -> EntryLimits | None:
    if not isinstance(raw, Mapping):
        return None
    values = []
    for key, cap in (("total", 500), ("perDay", 20), ("perWeekDays", 7), ("perMonth", 100)):
        value = raw.get(key)
        if key in raw and (type(value) is not int or not 1 <= value <= cap):
            return None
        values.append(value)
    minutes = raw.get("visitMinutes", 180)
    if (not any(v is not None for v in values) or type(minutes) is not int
            or not 30 <= minutes <= 720 or minutes % 30):
        return None
    return EntryLimits(*values, minutes)


@dataclass(frozen=True)
class EntryUsage:
    as_of: datetime | None
    list_from: datetime
    total_before: int
    visits: tuple[datetime, ...]
    term_start: date
    term_end: date
    from_: date | None


def _date(raw) -> date:
    if not isinstance(raw, str) or len(raw) != 10:
        raise ValueError("expected ISO date")
    return date.fromisoformat(raw)


def _datetime(raw) -> datetime:
    if not isinstance(raw, str) or len(raw) < 16 or raw[10] != "T":
        raise ValueError("expected ISO local datetime")
    value = datetime.fromisoformat(raw)
    if value.tzinfo is not None:
        raise ValueError("expected naive gym-local datetime")
    return value


def parse_usage(raw) -> EntryUsage | None:
    if not isinstance(raw, Mapping):
        return None
    try:
        start, end = _date(raw.get("termStart")), _date(raw.get("termEnd"))
        before, visits = raw.get("totalBefore"), raw.get("visits")
        if end < start or type(before) is not int or not isinstance(visits, list):
            return None
        return EntryUsage(
            _datetime(raw["asOf"]) if raw.get("asOf") is not None else None,
            _datetime(raw.get("listFrom")), before, tuple(_datetime(v) for v in visits),
            start, end, _date(raw["from"]) if raw.get("from") is not None else None,
        )
    except (TypeError, ValueError, OverflowError):
        return None


def add_months(d: date, k: int) -> date:
    year, month0 = divmod(d.year * 12 + d.month - 1 + k, 12)
    return date(year, month0 + 1, min(d.day, monthrange(year, month0 + 1)[1]))


def group_visits(passes: Iterable[datetime], visit_minutes: int) -> list[datetime]:
    visits = []
    length = timedelta(minutes=visit_minutes)
    for p in sorted(passes):
        if not visits or p >= visits[-1] + length:
            visits.append(p)
    return visits


@dataclass(frozen=True)
class EntryState:
    today: int
    week_days: int
    month: int
    total_used: int
    held: bool
    blocked_until: datetime | None
    exhausted: bool
    reasons: frozenset


def evaluate(limits, term_start, term_end, from_, frozen, visit_starts, adjustment_sum, now) -> EntryState:
    if limits is None or not any(v is not None for v in (
            limits.total, limits.per_day, limits.per_week_days, limits.per_month)):
        return EntryState(0, 0, 0, 0, False, None, False, frozenset())
    day = now.date()
    from_ = term_start if from_ is None else from_
    week = day - timedelta(days=day.weekday())
    k = max(0, (day.year - term_start.year) * 12 + day.month - term_start.month)
    if k > 0 and add_months(term_start, k) > day:
        k -= 1
    month_start, month_end = add_months(term_start, k), add_months(term_start, k + 1)
    today = month = total = 0
    week_dates = set()
    last = None
    for visit in sorted(visit_starts):
        d = visit.date()
        if visit <= now:
            last = visit
        if term_start <= d <= term_end:
            total += 1
        if d < from_:
            continue
        if d == day:
            today += 1
        if week <= d < week + timedelta(weeks=1):
            week_dates.add(d)
        if month_start <= d < month_end:
            month += 1
    total_used = max(0, total - adjustment_sum)
    exhausted = limits.total is not None and total_used >= limits.total
    reasons = set()
    blocked_until = None
    running = last is not None and now < last + timedelta(minutes=limits.visit_minutes)
    if not frozen and not running:
        timed = {}
        lead = timedelta(minutes=LEAD_MINUTES)
        if limits.per_day is not None and today >= limits.per_day:
            timed["DAY"] = datetime.combine(day + timedelta(days=1), time()) - lead
        if (limits.per_week_days is not None
                and sum(d < day for d in week_dates) >= limits.per_week_days):
            timed["WEEK"] = datetime.combine(week + timedelta(weeks=1), time()) - lead
        if limits.per_month is not None and month >= limits.per_month:
            timed["MONTH"] = datetime.combine(month_end, time()) - lead
        for reason, release_at in timed.items():
            if now < release_at:
                reasons.add(reason)
                if blocked_until is None or release_at > blocked_until:
                    blocked_until = release_at
        if exhausted:
            reasons.add("TOTAL")
            blocked_until = None
    return EntryState(today, len(week_dates), month, total_used, bool(reasons),
                      blocked_until, exhausted, frozenset(reasons))


def merged_state(limits, usage, local_passes, now) -> EntryState:
    visits = group_visits((*usage.visits, *(p for p in local_passes if p >= usage.list_from)),
                          limits.visit_minutes)
    return evaluate(limits, usage.term_start, usage.term_end, usage.from_, False,
                    visits, -usage.total_before, now)

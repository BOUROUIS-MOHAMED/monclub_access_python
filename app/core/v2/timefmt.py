"""Lenient ISO-8601 reading and the one format the PC sends.

The backend sends three shapes (c7d4b532):
* socket ``serverTime``/``claimBy``/``at``: ``ISO_OFFSET_DATE_TIME`` truncated to millis, so
  0-3 fraction digits with trailing zeros stripped (``…T10:00:00.12+01:00``);
* REST ``LocalDateTime`` fields: Tunis local time, no offset, up to 6 fraction digits;
* ``CLOCK_SKEW`` ``details.serverTime``: ``LocalDateTime.toString()``, which drops the seconds
  when they are zero (``…T10:00``).
Python 3.11's ``fromisoformat`` is not relied on for these; one regex reads them all.

The PC sends every time as UTC with a ``Z`` and microseconds: the P2c-2 text fields convert an
offset time to gym time (``AccessPinSets.parseTime``), so a UTC time needs no knowledge of the
gym's offset.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Optional, Tuple

_ISO = re.compile(
    r"^\s*(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?"
    r"(Z|z|[+-]\d{2}:?\d{2})?\s*$"
)


def _parse(text) -> Optional[Tuple[_dt.datetime, Optional[int]]]:
    if not isinstance(text, str):
        return None
    m = _ISO.match(text)
    if not m:
        return None
    y, mo, d, h, mi, s, frac, off = m.groups()
    try:
        micro = int((frac or "0")[:6].ljust(6, "0"))
        naive = _dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s or 0), micro)
    except ValueError:
        return None
    if off is None:
        return naive, None
    if off in ("Z", "z"):
        return naive, 0
    sign = -1 if off[0] == "-" else 1
    digits = off[1:].replace(":", "")
    return naive, sign * (int(digits[:2]) * 3600 + int(digits[2:4]) * 60)


def to_epoch(text, *, default_offset_sec: Optional[int] = None) -> Optional[float]:
    """Seconds since the epoch, or None when unreadable, or when the text has no offset and
    no ``default_offset_sec`` is known (a local time cannot be placed without it)."""
    parsed = _parse(text)
    if parsed is None:
        return None
    naive, off = parsed
    if off is None:
        if default_offset_sec is None:
            return None
        off = int(default_offset_sec)
    aware = naive.replace(tzinfo=_dt.timezone(_dt.timedelta(seconds=off)))
    return aware.timestamp()


def utc_offset_of(text) -> Optional[int]:
    parsed = _parse(text)
    return None if parsed is None else parsed[1]


def local_seconds_between(start, end) -> Optional[float]:
    """``end - start`` for two times of the SAME clock (e.g. a claim answer's serverTime and
    finishBy, both Tunis local): no offset is needed."""
    a, b = _parse(start), _parse(end)
    if a is None or b is None:
        return None
    return (b[0] - a[0]).total_seconds()


def format_utc(epoch: float) -> str:
    moment = _dt.datetime.fromtimestamp(float(epoch), tz=_dt.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

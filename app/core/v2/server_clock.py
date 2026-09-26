"""The PC's estimate of the server's clock (owner decision 5a, 2026-09-26).

The backend refuses a P2c-2 write whose ``sentAt`` is more than 5 minutes from its own clock
(409 ``CLOCK_SKEW``) and orders ownership facts by the PCs' own times. The owner chose to keep
that rule and have the PC correct ITS OWN timestamps: measure the offset whenever the server
tells its time, smooth it, apply it to every time the PC sends, never let it go backwards, and
report it in the heartbeat.

* A sample is ``server_time - midpoint(send, receive)``; a round trip over ``MAX_RTT_SEC`` is
  not a sample (the midpoint would be off by up to half of it).
* The offset is the MEDIAN of the last ``WINDOW`` samples, so one wild answer moves nothing.
* ``now()`` = PC time + offset, and never lower than the last value it returned in this
  process: when the estimate moves back (a better sample, or the PC clock stepped back), the
  corrected time keeps advancing at ``SLEW_RATE`` of real time until the estimate catches up.
  Nothing is persisted as a time floor: a floor carried over from a run with a fast clock would
  keep ``sentAt`` ahead of the server after a restart.
* The offset itself is persisted, and reused after a restart only while younger than
  ``PERSISTED_MAX_AGE_SEC`` (a PC that was off all night has no measurement of today).
"""
from __future__ import annotations

import statistics
import threading
import time
from typing import Any, Callable, Dict, List, Optional

MAX_RTT_SEC = 5.0
WINDOW = 7
SLEW_RATE = 0.1
PERSISTED_MAX_AGE_SEC = 12 * 3600.0
PERSIST_EVERY_SEC = 60.0
_SANE_OFFSET_SEC = 10 * 365 * 86400.0


class ServerClock:
    def __init__(
        self,
        *,
        wall: Callable[[], float] = time.time,
        mono: Callable[[], float] = time.monotonic,
        persist: Optional[Callable[[Dict[str, Any]], None]] = None,
        load: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
    ) -> None:
        self._wall = wall
        self._mono = mono
        self._persist = persist
        self._lock = threading.Lock()
        self._samples: List[float] = []
        self._source = ""
        self._measured_at = 0.0
        self._utc_offset: Optional[int] = None
        self._last_issued: Optional[float] = None
        self._last_issued_mono = 0.0
        self._last_persist_mono: Optional[float] = None
        self._persisted_offset: Optional[float] = None
        if load is not None:
            try:
                row = load() or {}
                off = row.get("offset_sec")
                at = float(row.get("measured_at") or 0.0)
                if off is not None and 0.0 <= self._wall() - at <= PERSISTED_MAX_AGE_SEC:
                    self._persisted_offset = float(off)
                    self._source = str(row.get("source") or "persisted")
                    self._measured_at = at
                if row.get("utc_offset_sec") is not None:
                    self._utc_offset = int(row["utc_offset_sec"])
            except Exception:
                self._persisted_offset = None

    # ------------------------------------------------------------------ samples
    def add_sample(self, server_epoch: float, sent_wall: float, recv_wall: float, *, source: str) -> bool:
        try:
            server_epoch, sent_wall, recv_wall = float(server_epoch), float(sent_wall), float(recv_wall)
        except (TypeError, ValueError):
            return False
        rtt = recv_wall - sent_wall
        if rtt < 0 or rtt > MAX_RTT_SEC:
            return False
        offset = server_epoch - (sent_wall + recv_wall) / 2.0
        if abs(offset) > _SANE_OFFSET_SEC:
            return False
        with self._lock:
            self._samples.append(offset)
            del self._samples[:-WINDOW]
            self._source = str(source)
            self._measured_at = self._wall()
        self._maybe_persist()
        return True

    def set_utc_offset(self, seconds: Optional[int]) -> None:
        if seconds is None:
            return
        with self._lock:
            self._utc_offset = int(seconds)

    @property
    def utc_offset(self) -> Optional[int]:
        return self._utc_offset

    # ------------------------------------------------------------------ reading
    def offset(self) -> Optional[float]:
        with self._lock:
            return self._offset_locked()

    def _offset_locked(self) -> Optional[float]:
        if self._samples:
            return float(statistics.median(self._samples))
        return self._persisted_offset

    def has_sample(self) -> bool:
        with self._lock:
            return bool(self._samples) or self._persisted_offset is not None

    def now(self) -> float:
        with self._lock:
            off = self._offset_locked() or 0.0
            candidate = self._wall() + off
            mono = self._mono()
            last = self._last_issued
            if last is not None and candidate < last:
                candidate = last + max(0.0, mono - self._last_issued_mono) * SLEW_RATE
            self._last_issued = candidate
            self._last_issued_mono = mono
            return candidate

    def report(self) -> Optional[Dict[str, Any]]:
        """The heartbeat's ``clockOffsetSec`` block; None before any measurement."""
        with self._lock:
            off = self._offset_locked()
            if off is None:
                return None
            return {"offsetSec": round(off, 3), "samples": len(self._samples),
                    "source": self._source or "persisted"}

    # ------------------------------------------------------------------ persistence
    def _maybe_persist(self) -> None:
        if self._persist is None:
            return
        mono = self._mono()
        if self._last_persist_mono is not None and mono - self._last_persist_mono < PERSIST_EVERY_SEC:
            return
        self.flush()

    def flush(self) -> None:
        if self._persist is None:
            return
        with self._lock:
            off = self._offset_locked()
            if off is None:
                return
            row = {"offset_sec": off, "measured_at": self._measured_at, "source": self._source,
                   "samples": len(self._samples), "utc_offset_sec": self._utc_offset}
            self._last_persist_mono = self._mono()
        try:
            self._persist(row)
        except Exception:
            pass

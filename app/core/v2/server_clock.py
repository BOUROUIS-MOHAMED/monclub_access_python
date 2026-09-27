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
  One exception: a 409 ``CLOCK_SKEW`` (the server refused a time more than 5 min off) resets
  the estimate and the floor -- see ``add_sample(authoritative=True)``.
  Nothing is persisted as a time floor: a floor carried over from a run with a fast clock would
  keep ``sentAt`` ahead of the server after a restart.
* The offset itself is persisted, and reused after a restart only while younger than
  ``PERSISTED_MAX_AGE_SEC`` (a PC that was off all night has no measurement of today).
"""
from __future__ import annotations

import math
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
        # When each sample was taken (PC wall clock), parallel to ``_samples``: the heartbeat's
        # ``ageSec`` is the age of the OLDEST one in the window (lane 1, last-push contract §5.1).
        self._sample_walls: List[float] = []
        self._persisted_oldest_at: Optional[float] = None
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
                    oldest = row.get("oldest_at")
                    # A row saved before 2026-09-27 has no oldest_at: its age is then unknown
                    # (``measured_at`` is the NEWEST sample's time, which would call it fresh).
                    self._persisted_oldest_at = float(oldest) if oldest is not None else None
                if row.get("utc_offset_sec") is not None:
                    self._utc_offset = int(row["utc_offset_sec"])
            except Exception:
                self._persisted_offset = None

    # ------------------------------------------------------------------ samples
    def add_sample(self, server_epoch: float, sent_wall: float, recv_wall: float, *, source: str,
                   authoritative: bool = False) -> bool:
        """``authoritative``: the server just refused this PC's time (409 ``CLOCK_SKEW``), so the
        earlier samples are known wrong: the window restarts from this one (without it, one good
        sample never outvotes a wrong one -- the median of two is their mean), and the
        never-backwards floor is dropped. That is the ONE case where the corrected time may step
        back: the server refused every write stamped with the wrong estimate (more than 5 min
        off), so nothing it stored can be out of order; keeping the floor would keep every
        ``sentAt`` refused until real time caught up (found in the end-to-end run)."""
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
            if authoritative:
                self._samples = []
                self._sample_walls = []
                self._persisted_offset = None
                self._persisted_oldest_at = None
                self._last_issued = None
            self._samples.append(offset)
            self._sample_walls.append(self._wall())
            del self._samples[:-WINDOW]
            del self._sample_walls[:-WINDOW]
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
            out: Dict[str, Any] = {"offsetSec": round(off, 3), "samples": len(self._samples),
                                   "source": self._source or "persisted"}
            oldest = self._oldest_sample_at_locked()
            if oldest is not None:
                age = self._wall() - oldest
                # Measured on the PC's own clock; a negative age (the PC clock stepped back) is
                # not an age: left out, like an unknown one.
                if math.isfinite(age) and age >= 0.0:
                    out["ageSec"] = round(age, 1)
            return out

    def _oldest_sample_at_locked(self) -> Optional[float]:
        if self._samples:
            return min(self._sample_walls) if self._sample_walls else None
        return self._persisted_oldest_at

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
                   "samples": len(self._samples), "utc_offset_sec": self._utc_offset,
                   "oldest_at": self._oldest_sample_at_locked()}
            self._last_persist_mono = self._mono()
        try:
            self._persist(row)
        except Exception:
            pass


# The process's clock, set by the v2 runtime; read by code that records fact times (the
# removal log in db.py) without importing the runtime.
_default: Optional[ServerClock] = None


def set_default(clock: Optional[ServerClock]) -> None:
    global _default
    _default = clock


def get_default() -> Optional[ServerClock]:
    return _default


def corrected_now() -> tuple:
    """(epoch, corrected) -- the server-corrected time when a measurement exists, else the
    PC's own time with ``corrected=False`` (corrected later, at upload, with the offset then)."""
    clk = _default
    if clk is not None and clk.has_sample():
        return clk.now(), True
    return time.time(), False

"""Lightweight, exception-safe, non-blocking telemetry for MonClub Access.

Design rules (this is critical access-control software):
  * NEVER change behavior. Every public call swallows its own exceptions and
    returns quickly. A telemetry bug must never break a door, a poll, or a sync.
  * NEVER block a hot path. The only work done inline is building one log line.
    The periodic heartbeat runs on its own shared daemon thread.
  * NO new dependencies. Process counters use ctypes on Windows (psutil is used
    only if it already happens to be importable).

What it captures (mapped to the two observed production failure modes):
  1. Type-2 "can't start new thread" / daily full lockup → process resource
     snapshot (Python thread count, private/working-set bytes, OS handle count),
     logged periodically AND at every thread-spawn failure site.
  2. Type-1 hourly partial freeze → per-worker STATE heartbeat. Each device
     worker reports what it is doing (polling / full_sync / member_sync /
     cache_load / reconnecting / draining / idle). The heartbeat thread logs
     every worker's current state and, crucially, raises a STALL warning when a
     worker has been stuck in one non-idle state longer than a threshold — that
     warning is the freeze, caught live, with its owner named.

It also exposes ``span()`` (timed, exception-safe context manager) and
``event()`` (one structured line) used to trace the popup, device-push and
sync pipelines.

Log lines are emitted on the ``zkapp.telemetry`` logger (same rotating file as
the rest of the app) as ``key=value`` pairs so they are trivial to grep.
"""
from __future__ import annotations

import gc
import logging
import os
import sys
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Optional

logger = logging.getLogger("zkapp.telemetry")

# Memory-leak diagnostics. tracemalloc names the exact Python source lines that
# hold the most memory; comparing its total to the process private bytes also
# tells us whether a leak is Python-side (tracemalloc grows) or native/C/DLL
# (tracemalloc flat while private_mb climbs). Enabled by default for the leak
# hunt; set MONCLUB_MEMPROFILE=0 to disable. depth=1 keeps the overhead small.
_tracemalloc_on = False
try:
    if os.environ.get("MONCLUB_MEMPROFILE", "1") != "0":
        import tracemalloc as _tracemalloc
        _tracemalloc.start(1)
        _tracemalloc_on = True
    else:
        _tracemalloc = None
except Exception:
    _tracemalloc = None
    _tracemalloc_on = False

# --------------------------------------------------------------------------- #
# Process resource snapshot (threads / memory / handles)
# --------------------------------------------------------------------------- #

_proc_backend = "minimal"
_psutil = None
try:  # psutil is not a hard dependency — use it only if already installed.
    import psutil as _psutil  # type: ignore

    _proc_backend = "psutil"
    _psutil_proc = _psutil.Process(os.getpid())
except Exception:
    _psutil = None
    _psutil_proc = None

# ctypes / Windows fallback (the production target is 32-bit Windows Python).
_ctypes_ready = False
if _proc_backend == "minimal" and os.name == "nt":
    try:
        import ctypes
        from ctypes import wintypes

        class _PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
                ("PrivateUsage", ctypes.c_size_t),
            ]

        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # GetProcessMemoryInfo lives in psapi on older systems, kernel32 (K32*)
        # on newer ones. Try psapi first, fall back to kernel32.
        try:
            _psapi = ctypes.WinDLL("psapi", use_last_error=True)
            _GetProcessMemoryInfo = _psapi.GetProcessMemoryInfo
        except Exception:
            _GetProcessMemoryInfo = _kernel32.K32GetProcessMemoryInfo
        _GetCurrentProcess = _kernel32.GetCurrentProcess
        _GetProcessHandleCount = _kernel32.GetProcessHandleCount
        # Declare arg/return types so the process HANDLE (pseudo-handle -1) is
        # not truncated on 64-bit Python — without this the memory/handle reads
        # silently fail. (Production is 32-bit, but keep it correct on both.)
        _GetCurrentProcess.argtypes = []
        _GetCurrentProcess.restype = wintypes.HANDLE
        _GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_PROCESS_MEMORY_COUNTERS_EX),
            wintypes.DWORD,
        ]
        _GetProcessMemoryInfo.restype = wintypes.BOOL
        _GetProcessHandleCount.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)
        ]
        _GetProcessHandleCount.restype = wintypes.BOOL
        _ctypes_ready = True
        _proc_backend = "ctypes"
    except Exception:
        _ctypes_ready = False


def proc_snapshot() -> Dict[str, Any]:
    """Return a process resource snapshot. Never raises.

    Keys (any may be absent if a backend can't supply it):
      threads        — live Python Thread objects (threading.active_count())
      rss_mb         — working set / resident set in MiB
      private_mb     — private (commit) bytes in MiB  ← the 32-bit ceiling metric
      handles        — open OS handle count (Windows)
      backend        — which provider answered
    """
    snap: Dict[str, Any] = {"backend": _proc_backend}
    try:
        snap["threads"] = threading.active_count()
    except Exception:
        pass
    try:
        if _proc_backend == "psutil" and _psutil_proc is not None:
            mi = _psutil_proc.memory_info()
            snap["rss_mb"] = round(getattr(mi, "rss", 0) / 1048576.0, 1)
            # private bytes ≈ VMS on posix; on Windows psutil exposes 'private'
            priv = getattr(mi, "private", None)
            if priv is None:
                priv = getattr(mi, "vms", 0)
            snap["private_mb"] = round((priv or 0) / 1048576.0, 1)
            try:
                snap["handles"] = _psutil_proc.num_handles()  # Windows only
            except Exception:
                pass
        elif _proc_backend == "ctypes" and _ctypes_ready:
            counters = _PROCESS_MEMORY_COUNTERS_EX()
            counters.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS_EX)
            h = _GetCurrentProcess()
            if _GetProcessMemoryInfo(h, ctypes.byref(counters), counters.cb):
                snap["rss_mb"] = round(counters.WorkingSetSize / 1048576.0, 1)
                snap["private_mb"] = round(counters.PrivateUsage / 1048576.0, 1)
            hc = wintypes.DWORD(0)
            if _GetProcessHandleCount(h, ctypes.byref(hc)):
                snap["handles"] = int(hc.value)
    except Exception:
        pass
    return snap


def _fmt(fields: Dict[str, Any]) -> str:
    parts = []
    for k, v in fields.items():
        if v is None:
            continue
        parts.append(f"{k}={v}")
    return " ".join(parts)


def event(name: str, **fields: Any) -> None:
    """Emit one structured telemetry line. Never raises."""
    try:
        logger.info("[T] %s %s", name, _fmt(fields))
    except Exception:
        pass


def warn(name: str, **fields: Any) -> None:
    """Emit a WARNING-level telemetry line. Never raises."""
    try:
        logger.warning("[T] %s %s", name, _fmt(fields))
    except Exception:
        pass


def snapshot_event(name: str, **fields: Any) -> None:
    """Emit a telemetry line annotated with the current process snapshot."""
    try:
        merged = dict(fields)
        merged.update(proc_snapshot())
        logger.info("[T] %s %s", name, _fmt(merged))
    except Exception:
        pass


def thread_spawn_failure(where: str, **fields: Any) -> None:
    """Log a thread-creation failure with a full process snapshot (Type-2).

    Call this from any ``except RuntimeError`` that wraps a ``Thread.start()``.
    Logged at ERROR with the resource snapshot so the next daily lockup names
    the exhausted resource instead of leaving us to infer it.
    """
    try:
        merged = {"where": where}
        merged.update(fields)
        merged.update(proc_snapshot())
        logger.error("[T] THREAD_SPAWN_FAILURE %s", _fmt(merged))
    except Exception:
        pass


def mem_diagnostics(top: int = 15) -> None:
    """Name the residual memory leak's source — don't guess it.

    Emits up to two lines (runs on the heartbeat thread, never blocks the worker):
      MEM_DIAG  — live Python object count + top object types by count + the
                  process private/rss bytes. A type whose count climbs across
                  successive samples is the leaking Python structure.
      MEM_TRACE — (tracemalloc on) total Python-tracked bytes + the top source
                  lines by retained size. KEY DISCRIMINATOR: if py_tracked_mb
                  stays flat while MEM_DIAG private_mb climbs, the leak is
                  NATIVE (e.g. plcommpro.dll per-call), not Python — so the fix
                  is to cut call volume, not chase Python code.
    """
    private_mb = None
    try:
        snap = proc_snapshot()
        private_mb = snap.get("private_mb")
        # NOTE: gc.get_objects() only returns GC-TRACKED containers — CPython
        # leaves dicts/tuples of atomic values, and all bytes/str/int, untracked.
        # So this census is a SUPPLEMENTARY hint only; MEM_TRACE below (tracemalloc)
        # is the authoritative source — it tracks every allocation.
        from collections import Counter
        objs = gc.get_objects()
        n = len(objs)
        cnt: "Counter[str]" = Counter()
        for o in objs:
            cnt[type(o).__name__] += 1
        del objs
        top_types = ";".join(f"{name}={c}" for name, c in cnt.most_common(top))
        logger.info(
            "[T] MEM_DIAG tracked_objects=%d private_mb=%s rss_mb=%s gc=%s top=%s",
            n, private_mb, snap.get("rss_mb"), gc.get_count(), top_types,
        )
    except Exception:
        pass
    if not _tracemalloc_on or _tracemalloc is None:
        return
    try:
        cur, peak = _tracemalloc.get_traced_memory()
        py_mb = cur / 1048576.0
        stats = _tracemalloc.take_snapshot().statistics("lineno")[:10]
        lines = []
        for s in stats:
            fr = s.traceback[0]
            fname = fr.filename.replace("\\", "/").split("/")[-1]
            lines.append(f"{fname}:{fr.lineno}={s.size // 1024}KB/{s.count}")
        # KEY DISCRIMINATOR on one line: if py_tracked_mb stays flat across
        # samples while private_mb climbs, the residual leak is NATIVE (the
        # plcommpro.dll per-call leak), not Python.
        logger.info(
            "[T] MEM_TRACE py_tracked_mb=%.1f private_mb=%s peak_mb=%.1f top=%s",
            py_mb, private_mb, peak / 1048576.0, " | ".join(lines),
        )
    except Exception:
        pass


@contextmanager
def span(name: str, **fields: Any):
    """Timed, exception-safe span. Logs start, then end with duration_ms.

    On exception it logs the failure (with duration) and RE-RAISES — telemetry
    must not swallow real errors.
    """
    t0 = time.monotonic()
    try:
        logger.debug("[T] %s.start %s", name, _fmt(fields))
    except Exception:
        pass
    try:
        yield
    except BaseException as exc:  # noqa: BLE001 - log then re-raise
        try:
            dur = (time.monotonic() - t0) * 1000.0
            logger.warning(
                "[T] %s.error dur_ms=%.0f err=%s %s",
                name, dur, type(exc).__name__, _fmt(fields),
            )
        except Exception:
            pass
        raise
    else:
        try:
            dur = (time.monotonic() - t0) * 1000.0
            logger.info("[T] %s.end dur_ms=%.0f %s", name, dur, _fmt(fields))
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Per-worker state heartbeat (Type-1 stall detection)
# --------------------------------------------------------------------------- #


class _WorkerState:
    __slots__ = ("state", "since", "detail", "polls", "events", "last_event_mono")

    def __init__(self) -> None:
        self.state = "init"
        self.since = time.monotonic()
        self.detail = ""
        self.polls = 0
        self.events = 0
        self.last_event_mono = 0.0


_states: Dict[str, _WorkerState] = {}
_states_lock = threading.Lock()

_hb_thread: Optional[threading.Thread] = None
_hb_stop = threading.Event()
# Stalls are scanned every interval (sharp freeze detection); a healthy worker's
# routine heartbeat is only emitted every Nth tick to keep log volume sane.
_hb_interval_sec = 10.0
_hb_routine_every = 3  # routine WORKER_HB cadence = interval * this (≈30s)
# A non-idle state held longer than this is reported as a STALL (the freeze).
_hb_stall_warn_sec = 25.0
_proc_log_every_sec = 60.0
# Object/line-level memory census cadence (heavier than PROC_HB, so less often).
_mem_diag_every_sec = 300.0
# States that are normal to sit in for a while (don't warn on these).
_idle_states = {"idle", "init", "stopped", "waiting"}


def set_state(worker: str, state: str, detail: str = "") -> None:
    """Record what a worker is doing now. O(1), never raises, never blocks.

    ``worker`` is a stable id like ``"ULTRA:5"``. Changing state stamps a new
    'since' so the heartbeat can measure time-in-state (and catch stalls).
    """
    try:
        now = time.monotonic()
        with _states_lock:
            st = _states.get(worker)
            if st is None:
                st = _WorkerState()
                _states[worker] = st
            if st.state != state:
                st.state = state
                st.since = now
            st.detail = detail or st.detail if state == st.state else detail
        _ensure_heartbeat()
    except Exception:
        pass


def note_poll(worker: str, events: int = 0) -> None:
    """Count a completed poll cycle (events>0 means real activity drained)."""
    try:
        now = time.monotonic()
        with _states_lock:
            st = _states.get(worker)
            if st is None:
                st = _WorkerState()
                _states[worker] = st
            st.polls += 1
            if events:
                st.events += events
                st.last_event_mono = now
    except Exception:
        pass


def clear_worker(worker: str) -> None:
    try:
        with _states_lock:
            _states.pop(worker, None)
    except Exception:
        pass


def _ensure_heartbeat() -> None:
    global _hb_thread
    if _hb_thread is not None and _hb_thread.is_alive():
        return
    try:
        _hb_stop.clear()
        _hb_thread = threading.Thread(
            target=_heartbeat_loop, name="telemetry-heartbeat", daemon=True
        )
        _hb_thread.start()
    except Exception:
        # If we cannot even start the heartbeat (e.g. thread exhaustion), stay
        # silent — the spawn-failure path will already be logging the snapshot.
        _hb_thread = None


def _heartbeat_loop() -> None:
    last_proc_log = 0.0
    last_mem_diag = 0.0
    tick = 0
    try:
        snapshot_event("HEARTBEAT_START")
        event("MEMPROFILE", tracemalloc=_tracemalloc_on)
    except Exception:
        pass
    while not _hb_stop.is_set():
        try:
            _hb_stop.wait(_hb_interval_sec)
            if _hb_stop.is_set():
                break
            tick += 1
            emit_routine = (tick % max(1, _hb_routine_every)) == 0
            now = time.monotonic()
            with _states_lock:
                items = [(w, st.state, now - st.since, st.detail, st.polls,
                          st.events, st.last_event_mono) for w, st in _states.items()]
            for (w, state, in_state, detail, polls, events, last_evt) in items:
                # A worker stuck in a non-idle state past the threshold IS the
                # Type-1 freeze, caught while it is happening. Scanned every
                # tick so the freeze is reported within one interval.
                if state not in _idle_states and in_state >= _hb_stall_warn_sec:
                    warn(
                        "WORKER_STALL", worker=w, state=state,
                        in_state_s=round(in_state, 1), detail=detail,
                        polls=polls, events=events,
                    )
                elif emit_routine:
                    event(
                        "WORKER_HB", worker=w, state=state,
                        in_state_s=round(in_state, 1), polls=polls, events=events,
                    )
            # Periodic process snapshot (Type-2 trend).
            if now - last_proc_log >= _proc_log_every_sec:
                last_proc_log = now
                snapshot_event("PROC_HB")
            # Periodic memory census to pinpoint the residual leak's source.
            if now - last_mem_diag >= _mem_diag_every_sec:
                last_mem_diag = now
                mem_diagnostics()
        except Exception:
            # Heartbeat must survive anything.
            try:
                time.sleep(_hb_interval_sec)
            except Exception:
                pass


def configure(*, interval_sec: Optional[float] = None,
              stall_warn_sec: Optional[float] = None,
              proc_log_every_sec: Optional[float] = None) -> None:
    """Optional runtime tuning of the heartbeat cadence/thresholds."""
    global _hb_interval_sec, _hb_stall_warn_sec, _proc_log_every_sec
    try:
        if interval_sec is not None:
            _hb_interval_sec = float(interval_sec)
        if stall_warn_sec is not None:
            _hb_stall_warn_sec = float(stall_warn_sec)
        if proc_log_every_sec is not None:
            _proc_log_every_sec = float(proc_log_every_sec)
    except Exception:
        pass


def stop() -> None:
    try:
        _hb_stop.set()
    except Exception:
        pass


def start() -> None:
    """Explicitly start the heartbeat (also auto-starts on first set_state)."""
    _ensure_heartbeat()

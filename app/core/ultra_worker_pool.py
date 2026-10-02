"""The workers of a running ULTRA engine, one device at a time (ULTRA merge, spec 2026-10-02
section 6 "Taking effect": a mode or In-service change applies without restarting Access).

Moved out of ultra_engine.py so that file shrinks (spec section 9): UltraEngine.start's worker
loop (start_worker), UltraEngine.refresh_devices (refresh_copies) and the watchdog's restart
(restart_if_dead). New: reconcile, which starts the worker of a device that became ULTRA and stops
the worker of one that left ULTRA or went out of service without touching the others, and
WorkerStop, each worker's own stop flag, so one worker can stop while the engine runs.

Every function takes the UltraEngine and uses its fields (_workers, _worker_restart_lock,
_stop_event, _popup_q, _history_q, _cfg, _sync_scheduler, _logger, _running) and its worker
factory _new_worker, resolved at call time (tests patch UltraDeviceWorker or the factory).
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from app.core.device_service_gate import device_in_service
from app.core.v2 import lease_gate as _lease_gate


def _mode(device: Dict[str, Any]) -> str:
    return str(device.get("accessDataMode") or device.get("access_data_mode") or "").strip().upper()


def _device_id(device: Dict[str, Any]) -> int:
    try:
        return int(device.get("id", 0))
    except (TypeError, ValueError):
        return 0


class WorkerStop:
    """A worker's own stop flag that also follows the engine's. ``is_set`` and ``wait`` -- the two
    calls UltraDeviceWorker makes on ``_stop_evt`` -- see either flag; ``set`` stops this worker
    only. ``wait`` sleeps in short slices so an engine stop is seen within a quarter second."""

    _SLICE_SEC = 0.25

    def __init__(self, engine_stop: threading.Event) -> None:
        self._engine_stop = engine_stop
        self._own = threading.Event()

    def set(self) -> None:
        self._own.set()

    def is_set(self) -> bool:
        return self._own.is_set() or self._engine_stop.is_set()

    def wait(self, timeout: Optional[float] = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + max(0.0, float(timeout))
        while not self.is_set():
            if deadline is None:
                step = self._SLICE_SEC
            else:
                step = min(self._SLICE_SEC, deadline - time.monotonic())
                if step <= 0:
                    return self.is_set()
            self._own.wait(step)
        return True


def devices_to_drive(devices: Any) -> List[Dict[str, Any]]:
    """ULTRA devices in service that this PC drives (driver lease): exactly the ones with a worker."""
    ultra = [d for d in (devices or [])
             if isinstance(d, dict) and _mode(d) == "ULTRA" and device_in_service(d)]
    return _lease_gate.filter_devices(ultra)


def in_service_only(devices: Any, logger: Any) -> List[Dict[str, Any]]:
    """The devices in service; one log line for each one left out (UltraEngine.start)."""
    kept: List[Dict[str, Any]] = []
    for d in devices or []:
        if device_in_service(d):
            kept.append(d)
        else:
            logger.info(
                "[ULTRA] device id=%s name=%r out of service (active/accessDevice off): no worker",
                d.get("id"), d.get("name"),
            )
    return kept


def _build_worker(engine: Any, device: Dict[str, Any], settings: Dict[str, Any], stop: Any) -> Any:
    sched = engine._sync_scheduler
    return engine._new_worker(
        device=device,
        settings=settings,
        popup_q=engine._popup_q,
        history_q=engine._history_q,
        stop_event=stop,
        cfg=engine._cfg,
        on_full_sync_started=(sched._handle_worker_full_sync_started if sched else None),
        on_full_sync_finished=(sched._handle_worker_full_sync_finished if sched else None),
    )


def start_worker(engine: Any, device: Dict[str, Any], settings: Dict[str, Any]) -> bool:
    """Build and start one worker with its own stop flag; it joins _workers even if start fails
    (the watchdog then restarts it), as UltraEngine.start always did."""
    device_id = _device_id(device)
    worker = _build_worker(engine, device, settings, WorkerStop(engine._stop_event))
    engine._workers[device_id] = worker
    try:
        worker.start()
        engine._logger.info(
            "[ULTRA] Worker thread started for device id=%s name=%r", device_id, device.get("name"))
        return True
    except Exception as exc:
        engine._logger.error("[ULTRA] Worker thread start FAILED for device id=%s: %s", device_id, exc)
        return False


def stop_worker(engine: Any, device_id: int, *, join_timeout: float = 10.0) -> None:
    """Remove one worker from _workers (so the watchdog leaves it alone), stop it and join it.
    A worker still in a push stops at its next loop turn after the push."""
    worker = engine._workers.pop(int(device_id), None)
    if worker is None:
        return
    stop = getattr(worker, "_stop_evt", None)
    if stop is None or stop is engine._stop_event or not hasattr(stop, "set"):
        engine._logger.warning("[ULTRA:%s] worker has no stop flag of its own; it stops with the engine",
                               device_id)
    else:
        stop.set()
    try:
        worker.join(timeout=join_timeout)
    except RuntimeError:
        pass  # never started (a test harness)
    if worker.is_alive():
        engine._logger.warning("[ULTRA:%s] worker did not stop within %.0f s", device_id, join_timeout)
    engine._logger.info(
        "[ULTRA:%s] worker stopped (device left ULTRA, out of service, or not driven here)", device_id)


def refresh_copies(engine: Any, devices: Any, *, update_scheduler: bool = True) -> int:
    """Refresh each running worker's device row in place (was UltraEngine.refresh_devices).

    Workers keep their device dict (allowedMemberships, doorIds, pinScheme, the card choice...);
    after a sync or a fast patch the database is newer. A worker's copy follows the database
    whatever its lease says (review R1-F5); the scheduler's list follows the lease and In service
    (a turnstile this PC does not drive, or one out of service, is never pushed) and is replaced
    only when update_scheduler is True (review R2-4). Returns the number of workers refreshed.
    """
    if not engine._running:
        return 0
    from app.core.settings_reader import normalize_device_settings

    ultra_all = [d for d in (devices or []) if isinstance(d, dict) and _mode(d) == "ULTRA"]
    scheduled = _lease_gate.filter_devices([d for d in ultra_all if device_in_service(d)])
    refreshed = 0
    for d in ultra_all:
        device_id = _device_id(d)
        if device_id <= 0:
            continue
        worker = engine._workers.get(device_id)
        if worker is None:
            continue
        try:
            settings = normalize_device_settings(d)
            d["_settings"] = settings
            worker.update_device(d, settings)
            refreshed += 1
        except Exception as exc:
            engine._logger.warning("[ULTRA:%s] refresh_devices failed: %s", device_id, exc)
    if refreshed > 0:
        engine._logger.info("[ULTRA] refreshed %d worker device snapshot(s) in place", refreshed)
    if engine._sync_scheduler is not None and update_scheduler:
        try:
            engine._sync_scheduler.update_devices(scheduled)
        except Exception as exc:
            engine._logger.warning("[ULTRA] sync_scheduler.update_devices failed: %s", exc)
    return refreshed


def reconcile(engine: Any, devices: Any, *, stop_undriven: bool, refresh_copies_too: bool = True) -> Dict[str, int]:
    """Bring the running engine's workers to the device rows, without restarting it.

    Stops the worker of a device that is no longer ULTRA, no longer in service or gone -- and, with
    ``stop_undriven`` (the sync tick), of one this PC no longer drives; the fast path keeps such a
    worker with a fresh copy (review R1-F5). Starts a worker for every driven ULTRA device in
    service that has none, BEFORE the scheduler's list is replaced (review R1-F2: the scheduler
    pushes a device without a worker over its own session), and asks the scheduler for that
    worker's first pass -- the pass an engine start runs (UltraSyncScheduler._run, "startup"),
    not in manual-sync mode. Then refreshes the copies; the scheduler's whole list only when every
    worker is driven (review R2-4), but a stopped device always leaves it, so the scheduler never
    pushes a device whose worker was just stopped.
    """
    counts = {"started": 0, "stopped": 0, "refreshed": 0}
    if not engine._running:
        return counts
    from app.core.settings_reader import normalize_device_settings

    ultra = [d for d in (devices or []) if isinstance(d, dict) and _mode(d) == "ULTRA"
             and device_in_service(d) and _device_id(d) > 0]
    driven = _lease_gate.filter_devices(ultra)
    driven_ids = {_device_id(d) for d in driven}
    keep_ids = driven_ids if stop_undriven else {_device_id(d) for d in ultra}
    stopped_ids: set = set()
    started_ids: set = set()
    with engine._worker_restart_lock:
        for device_id in sorted(set(engine._workers) - keep_ids):
            stop_worker(engine, device_id)
            stopped_ids.add(device_id)
        for d in driven:
            if _device_id(d) in engine._workers:
                continue
            settings = normalize_device_settings(d)
            d["_settings"] = settings
            if start_worker(engine, d, settings):
                started_ids.add(_device_id(d))
    counts["started"], counts["stopped"] = len(started_ids), len(stopped_ids)
    whole_list = driven_ids == set(engine._workers)
    if refresh_copies_too or started_ids or stopped_ids:
        counts["refreshed"] = refresh_copies(engine, ultra, update_scheduler=whole_list)
    sched = engine._sync_scheduler
    if sched is not None and stopped_ids and not whole_list:
        current = list(getattr(sched, "_devices", []) or [])
        sched.update_devices([d for d in current if _device_id(d) not in stopped_ids])
    if sched is not None and started_ids:
        try:
            manual = bool(sched._manual_sync_mode())
        except Exception:
            manual = False
        if not manual:
            sched.request_sync_now(device_ids=set(started_ids), reason="worker-started")
    return counts


def restart_if_dead(engine: Any, device_id: int, worker: Any) -> None:
    """The watchdog's restart of one dead worker, with the same device row, settings and stop flag.
    A worker no longer in _workers (stopped on purpose) or already replaced is left alone."""
    if worker.is_alive():
        return
    with engine._worker_restart_lock:
        current = engine._workers.get(device_id)
        if current is not worker or current.is_alive():
            return
        engine._logger.error("[ULTRA:%s] watchdog: worker thread is dead - restarting", device_id)
        try:
            stop = getattr(worker, "_stop_evt", None) or WorkerStop(engine._stop_event)
            new_worker = _build_worker(engine, worker._device, worker._settings, stop)
            new_worker.start()
            engine._workers[device_id] = new_worker
            if engine._sync_scheduler is not None:
                engine._sync_scheduler.wake_pending_sync()
            engine._logger.info("[ULTRA:%s] watchdog: worker restarted OK", device_id)
        except Exception as exc:
            engine._logger.error("[ULTRA:%s] watchdog: worker restart FAILED: %s", device_id, exc)

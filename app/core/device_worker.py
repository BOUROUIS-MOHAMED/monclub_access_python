"""
device_worker.py — per-device persistent worker threads for ZKTeco sync.

Replaces the ThreadPoolExecutor(max_workers=4) pattern in DeviceSyncEngine
with one daemon thread per device:

    - Zero spin-up latency: thread is already running when a job arrives.
    - Latest-wins semantics: a new job supersedes any queued (not-yet-started)
      job, so rapid successive triggers collapse into a single push.
    - Per-device serialization: a device never runs two syncs in parallel.
    - Connect-per-batch: the SDK connection is opened + closed inside each
      job execution (ZKTeco firmware drops idle connections ~30 s).

Usage
-----
    manager = DeviceWorkerManager(sync_fn=engine._sync_one_device, logger=log)
    manager.update_devices(device_list)          # called every time devices refresh
    manager.dispatch_all(SyncJob(...))            # non-blocking, latest-wins
    manager.dispatch_to({device_id}, SyncJob(...))
    manager.stop_all()                            # on logout / shutdown
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Job type
# ---------------------------------------------------------------------------

@dataclass
class SyncJob:
    """Immutable unit of sync work dispatched to a DeviceWorker."""

    users: List[Dict[str, Any]]
    local_fp_index: Dict[str, List[Any]]
    default_door_id: int
    changed_ids: Optional[Set[int]] = field(default=None)


# ---------------------------------------------------------------------------
# Per-device worker
# ---------------------------------------------------------------------------

class DeviceWorker:
    """
    Persistent daemon thread that processes SyncJob tasks for one ZKTeco device.

    Latest-wins:  if submit() is called while the worker is still executing a
    previous job, the new job is stored as pending.  If another submit() arrives
    before execution resumes, it overwrites the pending job — ensuring only the
    freshest data is pushed.

    If submit() is called while the worker is idle, it wakes up immediately.
    """

    def __init__(
        self,
        *,
        device: Dict[str, Any],
        sync_fn: Callable[..., None],
        logger: Any = None,
    ) -> None:
        self._device = device
        self._sync_fn = sync_fn
        self._logger = logger or logging.getLogger(__name__)
        self._device_id: int = int(device.get("id", 0))
        self._device_name: str = str(device.get("name", ""))

        # Latest-wins job slot
        self._pending_job: Optional[SyncJob] = None
        self._job_lock = threading.Lock()
        self._job_available = threading.Event()

        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run_loop,
            name=f"DeviceWorker-{self._device_id}",
            daemon=True,
        )
        self._thread.start()
        self._logger.debug(
            "[DeviceWorker] started: device_id=%s name=%r",
            self._device_id, self._device_name,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def device_id(self) -> int:
        return self._device_id

    def update_device(self, device: Dict[str, Any]) -> None:
        """Swap in a refreshed device config dict (called on refreshDevices)."""
        self._device = device
        self._device_name = str(device.get("name", ""))

    def submit(self, job: SyncJob) -> None:
        """
        Queue a sync job (latest-wins).

        Thread-safe: may be called from any thread at any time.
        """
        with self._job_lock:
            self._pending_job = job  # overwrites any previously queued job
        self._job_available.set()  # wake worker if idle

    def stop(self) -> None:
        """Signal the worker to exit after the current job (if any) finishes."""
        self._stop_event.set()
        self._job_available.set()  # unblock waiting

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            self._job_available.wait()   # block until submit() or stop()
            self._job_available.clear()

            if self._stop_event.is_set():
                break

            with self._job_lock:
                job = self._pending_job
                self._pending_job = None

            if job is None:
                continue

            self._execute(job)

        self._logger.debug(
            "[DeviceWorker] exited: device_id=%s", self._device_id
        )

    def _execute(self, job: SyncJob) -> None:
        try:
            self._sync_fn(
                device=self._device,
                users=job.users,
                local_fp_index=job.local_fp_index,
                default_door_id=job.default_door_id,
                changed_ids=job.changed_ids,
            )
        except Exception as exc:
            self._logger.exception(
                "[DeviceWorker] unhandled error device_id=%s: %s",
                self._device_id, exc,
            )


# ---------------------------------------------------------------------------
# Worker pool manager
# ---------------------------------------------------------------------------

class DeviceWorkerManager:
    """
    Manages a pool of DeviceWorker instances — one per ZKTeco device.

    Lifecycle
    ---------
    1. Create once when the app boots (or after login):
           manager = DeviceWorkerManager(sync_fn=engine._sync_one_device, logger=log)

    2. After each getSyncData response that refreshes devices, call:
           manager.update_devices(filtered_device_list)
       Workers are created, updated, or removed automatically.

    3. After each getSyncData response, dispatch a job:
           manager.dispatch_all(SyncJob(users=..., ...))

    4. On logout / shutdown:
           manager.stop_all()

    Thread safety
    -------------
    All public methods acquire _lock before touching _workers, making it safe
    to call from the main thread while workers run in background threads.
    """

    def __init__(
        self,
        *,
        sync_fn: Callable[..., None],
        logger: Any = None,
    ) -> None:
        self._sync_fn = sync_fn
        self._logger = logger or logging.getLogger(__name__)
        self._workers: Dict[int, DeviceWorker] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_devices(self, devices: List[Dict[str, Any]]) -> None:
        """
        Reconcile the worker pool with the active device list.

        - New devices get a fresh DeviceWorker.
        - Existing devices get their config refreshed (update_device).
        - Removed devices have their worker stopped and deleted.
        """
        seen_ids: Set[int] = set()

        for dev in devices:
            raw_id = dev.get("id")
            if raw_id is None:
                continue
            dev_id = int(raw_id)
            seen_ids.add(dev_id)

            with self._lock:
                if dev_id in self._workers:
                    self._workers[dev_id].update_device(dev)
                else:
                    self._workers[dev_id] = DeviceWorker(
                        device=dev,
                        sync_fn=self._sync_fn,
                        logger=self._logger,
                    )
                    self._logger.info(
                        "[DeviceWorkerManager] created worker device_id=%s name=%r",
                        dev_id, dev.get("name"),
                    )

        # Evict workers for devices no longer in the list
        with self._lock:
            removed = set(self._workers) - seen_ids
        for dev_id in removed:
            self._logger.info(
                "[DeviceWorkerManager] removing worker for stale device_id=%s", dev_id
            )
            with self._lock:
                worker = self._workers.pop(dev_id, None)
            if worker:
                worker.stop()

    def dispatch_all(self, job: SyncJob) -> int:
        """
        Submit job to every known worker (latest-wins, non-blocking).
        Returns the number of workers that received the job.
        """
        with self._lock:
            workers = list(self._workers.values())
        for w in workers:
            w.submit(job)
        self._logger.debug(
            "[DeviceWorkerManager] dispatch_all: dispatched to %d workers", len(workers)
        )
        return len(workers)

    def dispatch_to(self, device_ids: Set[int], job: SyncJob) -> int:
        """
        Submit job only to the specified device workers (latest-wins, non-blocking).
        Returns the number of workers that actually received the job.

        Used for targeted hint-based dispatch (e.g., only devices serving a
        particular membership, from P4 dashboard hints).
        """
        count = 0
        for dev_id in device_ids:
            with self._lock:
                worker = self._workers.get(int(dev_id))
            if worker:
                worker.submit(job)
                count += 1
            else:
                self._logger.debug(
                    "[DeviceWorkerManager] dispatch_to: no worker for device_id=%s", dev_id
                )
        return count

    def stop_all(self) -> None:
        """Stop all workers gracefully. Called on logout or app shutdown."""
        with self._lock:
            workers = list(self._workers.values())
            self._workers.clear()
        for w in workers:
            w.stop()
        self._logger.info(
            "[DeviceWorkerManager] stopped %d workers", len(workers)
        )

    def active_device_ids(self) -> List[int]:
        """Return the list of device IDs currently managed."""
        with self._lock:
            return list(self._workers.keys())

    def worker_count(self) -> int:
        with self._lock:
            return len(self._workers)

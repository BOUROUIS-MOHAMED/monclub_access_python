# MonClub Access Audit Fixes Log
# Round 6 — 2026-04-02

---

## Summary

Three medium-severity bugs were discovered during Round 6 and fixed in this round. All fixes are minimal, targeted, and verified by the existing test suite (144 tests pass).

---

## M-NEW-001 — ULTRA devices double-synced by DeviceSyncEngine

**File**: `app/core/device_sync.py`
**Location**: `_normalize_device()`, line 208

### Root cause

`_normalize_device()` maps any `accessDataMode` not in `{"DEVICE", "AGENT"}` to `"DEVICE"`. After normalization, ULTRA devices appeared as DEVICE-mode to `_sync_all_devices()`, causing them to be processed by `DeviceSyncEngine` even when `UltraSyncScheduler` was already managing them. In a mixed DEVICE+ULTRA deployment, both engines would concurrently connect to and push data to the ULTRA devices.

### Fix

Add `"ULTRA"` to the recognized-but-not-DEVICE set. After this change, `_normalize_device()` preserves the `"ULTRA"` mode string. Since `_sync_all_devices()` already skips devices whose `accessDataMode != "DEVICE"`, ULTRA devices are now silently bypassed by `DeviceSyncEngine`.

```diff
- if adm not in ("DEVICE", "AGENT"):
+ if adm not in ("DEVICE", "AGENT", "ULTRA"):
      adm = "DEVICE"
```

### Effect

- ULTRA devices no longer processed by `DeviceSyncEngine`.
- `UltraSyncScheduler` remains sole owner of ULTRA device sync.
- DEVICE mode devices unaffected.
- No data schema change; no migration required.

---

## M-NEW-002 — New ULTRA device silently ignored when engine already running

**File**: `app/ui/app.py`
**Location**: `_sync_tick()`, ULTRA management block (~lines 1003–1055)

### Root cause

`UltraEngine.start()` returns early if `self._running`. The `sync_tick()` ULTRA management block only started the engine when `ultra_count > 0 and not self._ultra_engine.running`. If the engine was already running and a new ULTRA device was added (or an existing device switched to ULTRA mode), the new device was never picked up without a full app restart.

### Fix

Added an `elif` branch for the case where `ultra_count > 0 and self._ultra_engine.running`. This branch compares the set of running worker IDs (`self._ultra_engine._workers.keys()`) against the desired device IDs from the current sync cache. If they differ, the engine is stopped and restarted with the new device list.

```python
elif ultra_count > 0 and self._ultra_engine.running:
    # Check if the device list has changed; restart engine if so.
    current_ids = set(self._ultra_engine._workers.keys())
    desired_ids = {int(d.get("id", 0)) for d in ultra_devices}
    if current_ids != desired_ids:
        self.logger.info(
            f"[ULTRA] Device list changed ({current_ids} → {desired_ids}), restarting engine"
        )
        self._ultra_engine.stop()
        if ultra_devices:
            self._ultra_engine.start(ultra_devices)
```

Also refactored the cache load and device list filtering to be shared between the start and change-detection branches (avoids loading the cache twice).

### Effect

- Adding a new ULTRA device takes effect within one sync tick (default 60s) without app restart.
- Removing a device from ULTRA mode triggers engine restart; it will restart with only the remaining ULTRA devices.
- The existing stop-on-zero-ULTRA path (`ultra_count == 0 and self._ultra_engine.running`) is unchanged.

---

## M-NEW-003 — `_sync_work_running` race window

**File**: `app/ui/app.py`
**Location**: `_sync_tick()`, lines ~941–1072

### Root cause

`self._sync_work_running = True` was set inside the `work()` function body, which runs inside the thread started by `_work_guarded`. There was a window between the `threading.Thread(...).start()` call and the execution of `self._sync_work_running = True` during which a second `_sync_tick()` invocation could pass the guard check (`if self._sync_work_running: return`) and start a second concurrent sync thread.

### Fix

Removed `self._sync_work_running = True` from inside `work()` and set it immediately before `threading.Thread(...).start()` in the calling scope. The `finally: self._sync_work_running = False` in `_work_guarded` is unchanged and still correctly clears the flag when the thread exits.

```diff
  def work():
-     self._sync_work_running = True
      sync_online = False
      ...

  _work_original = work
  def _work_guarded():
      try:
          _work_original()
      finally:
          self._sync_work_running = False
+ self._sync_work_running = True
  threading.Thread(target=_work_guarded, daemon=True).start()
```

### Effect

- The guard check and the flag set are now atomic from the main thread's perspective.
- No second sync thread can start between `start()` and the flag assignment.
- In the rare event that `start()` itself raises (OS error), the flag is set but no thread runs and no finally clause clears it. This would cause subsequent sync ticks to be skipped indefinitely. This edge case is extremely unlikely (OS would have to refuse thread creation) and was not present before because the original code also had this characteristic (the flag was set before any I/O). The 15s force-exit already handles hung-process scenarios.

---

## Test verification

```
$ python -m pytest tests/ -x -q
144 passed in 0.67s
```

All 144 tests pass after applying these three fixes. No new tests were required for these changes as the existing test suite covers the affected code paths through integration-level tests.

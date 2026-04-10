# Near-Real-Time Sync — Implementation Reference

## Background

MonClub Access previously relied on a 45-second polling cycle (`ChangeDetectorService`) and a
periodic full sync tick to push member data to ZKTeco devices. Two categories of problems
motivated this overhaul:

1. **Silent card-update failure (P0 bug)**: ZKTeco firmware silently accepts a duplicate
   `SetDeviceData(user)` call (same Pin), returns `rc=0`, but does NOT update `CardNo`.
   The hash was then saved as "successful" so the bug was invisible until a member tried to
   badge in.

2. **Scalability / responsiveness**: A single ThreadPoolExecutor pool created new threads
   per sync call; no persistent state per device; no way to skip unchanged members.

---

## P0 — Card Update Bug Fix

**Root cause**: `_delete_pin_if_exists` checked `if pin not in device_pins: return False`.
When `device_pins` is empty (read failed or device returned no rows), the delete was skipped
and the subsequent insert silently failed.

**Fix** (`app/core/device_sync.py`): Added `_delete_pin_unconditional(sdk, pin)` that always
issues the SDK delete across all tables (`templatev10`/`template`, `userauthorize`, `user`)
without consulting `device_pins`. ZKTeco `DeleteDeviceData` is idempotent — deleting a
non-existent pin is a no-op. All `pins_to_sync` pre-deletes now use the unconditional path.

---

## P1 — Pushing Policies

Three canonical push modes are resolved from `device.pushingToDevicePolicy`:

| Policy | Behaviour |
|--------|-----------|
| `INCREMENTAL` (default) | Hash-based delta: delete stale pins, delete-before-insert for changed pins |
| `FULL_REPLACE` | Nuke all device tables, re-push entire desired roster |
| `ADDITIVE_ONLY` | Push changed/new (delete-before-insert), never remove stale pins |

Backend enum → policy mapping in `_resolve_push_policy`:
- `DELETE_ALL_BEFORE_PUSHING` → `FULL_REPLACE`
- `PUSH_WITHOUT_DELETING` → `ADDITIVE_ONLY`
- Everything else → `INCREMENTAL`

`changed_ids` (delta hint from backend) is ignored for `FULL_REPLACE` so all pins are
always re-pushed.

---

## P2 — Per-Device Persistent Worker Threads

**Motivation**: ThreadPoolExecutor creates new threads per sync call; no per-device
serialization; rapid successive triggers could overlap or be redundant.

**Implementation** (`app/core/device_worker.py`):

```
DeviceWorkerManager
└── DeviceWorker (one per ZKTeco device, daemon thread)
      ├── _pending_job: SyncJob | None   (latest-wins slot)
      ├── _job_lock: threading.Lock
      └── _job_available: threading.Event
```

**Key design decisions**:

- **Latest-wins**: `submit(job)` overwrites any pending (not-yet-started) job with the
  newest data. If a job arrives while the worker is executing, it queues behind (not dropped).
- **Connect-per-batch**: The SDK connection is opened and closed inside each `_execute` call.
  ZKTeco firmware drops idle connections after ~30 s, so persistent connections are unreliable.
- **Lifecycle**: `DeviceWorkerManager.update_devices(devices)` reconciles the pool after each
  `getSyncData` response — creates workers for new devices, updates configs for existing ones,
  stops workers for removed devices.
- **Shutdown**: `stop_workers()` is called on both logout (`show_login`) and destroy to
  cleanly signal all daemon threads.

**Integration** (`app/core/device_sync.py`):
`DeviceSyncEngine.__init__` creates a `DeviceWorkerManager`. `_sync_all_devices` now
calls `_worker_manager.update_devices(...)` then `_worker_manager.dispatch_all(job)`
(non-blocking, returns immediately). The `ThreadPoolExecutor` is gone.

---

## P3 — Backend CDC Event Stream

**Files** (Spring Boot backend):

| File | Purpose |
|------|---------|
| `Models/AccessSyncEvent.java` | Lightweight event entity (~50 bytes/row) |
| `Repositories/AccessSyncEventRepository.java` | JPA repo with cursor query + bulk prune |
| `Configuration/SpringContextHolder.java` | Static ApplicationContext gateway for JPA listeners |
| `Models/Listeners/AccessSyncEntityListener.java` | JPA `@PostPersist/@PostUpdate/@PostRemove` listener |

**Entity schema** (`access_sync_event` table):

| Column | Type | Notes |
|--------|------|-------|
| `id` | BIGINT IDENTITY | Auto-increment cursor |
| `gymId` | BIGINT | Denormalized for fast per-gym scoping |
| `entityType` | VARCHAR(30) | `ACTIVE_MEMBERSHIP` \| `GYM_DEVICE` |
| `entityId` | BIGINT | PK of changed entity |
| `operation` | VARCHAR(10) | `CREATE` \| `UPDATE` \| `DELETE` |
| `priority` | VARCHAR(10) | `HIGH` \| `NORMAL` \| `LOW` |
| `membershipId` | BIGINT (nullable) | Membership type of AM event (for device routing) |
| `createdAt` | DATETIME | Set by `@PrePersist` |

Indexes: `(gymId, id)` — cursor-based scan; `(entityType, entityId)` — entity lookup;
`(createdAt)` — prune.

**Listener registration**: Both `ActiveMembership` and `GymDevice` now declare:
```java
@EntityListeners({AuditingEntityListener.class, AccessSyncEntityListener.class})
```

The listener uses `SpringContextHolder.getBean(AccessSyncEventRepository.class)` to save
events. All exceptions are caught and logged — a failed event write **never** rolls back the
primary transaction.

**Endpoint**: `GET /api/v1/manager/gym/access/v1/changes?sinceEventId={cursor}&limit={n}`

Response:
```json
{
  "gymId": 42,
  "sinceEventId": 100,
  "lastEventId": 115,
  "count": 15,
  "hasMore": false,
  "events": [{ "id", "entityType", "entityId", "operation", "priority", "membershipId", "createdAt" }]
}
```

**Retention**: Daily midnight cron prunes rows older than 14 days (added to
`DailyScheduleService.purgeOldDataAtMidnight`).

**Priority assignment**:
- `ActiveMembership` changes → always `HIGH` (`@PostUpdate` can't detect field-level changes)
- `GymDevice` changes → `NORMAL`

---

## P4 — Dashboard Sync Hint Payloads

**`LocalAccessService.ts`**: `triggerLocalAccessSync` now accepts an optional `SyncHint`:

```typescript
interface SyncHint {
  entityType?: 'ACTIVE_MEMBERSHIP' | 'GYM_DEVICE';
  entityId?: number | null;
  operation?: 'CREATE' | 'UPDATE' | 'DELETE';
  priority?: 'HIGH' | 'NORMAL' | 'LOW';
}
```

The hint is sent as the JSON body of the `POST /api/v2/sync/now` request.

**Updated call sites**:

| File | Action | Priority |
|------|--------|----------|
| `active-membership-form.tsx` | Update membership | HIGH |
| `active-membership-form.tsx` | Create single membership | HIGH |
| `active-membership-form.tsx` | Bulk create memberships | HIGH |
| `active-membership-fingerprints-dialog.tsx` | Delete fingerprint | HIGH |
| `active-membership-fingerprints-dialog.tsx` | Start fingerprint enroll | HIGH |
| `gym-devices-view.tsx` | Create / update device | NORMAL (was missing) |
| `gym-devices-view.tsx` | Delete device(s) | NORMAL (was missing) |

---

## P5 — Transaction Purge After Every Read

**Previous**: ZKTeco transaction table was cleared only in a 2-5 AM window.

**Fix** (`app/core/device_attendance.py`): After each successful `_read_device_transactions`
call, an auto-clear runs immediately (controlled by `clear_transactions_after_read` global
setting, defaults `True`). The 2-5 AM window remains as a safety-net drain.

---

## P6 — Member Shadow Table (Diff Detection)

**Purpose**: Detect which members actually changed between sync cycles so we can narrow
`changed_ids` and avoid re-pushing unchanged pins.

**Table** (`member_shadow` in SQLite):

| Column | Notes |
|--------|-------|
| `active_membership_id` | PK |
| `pin`, `full_name`, `card_id`, `second_card_id` | Access-relevant fields |
| `membership_id`, `valid_from`, `valid_to` | Date/scope fields |
| `fp_hash` | SHA-1 of sorted fingerprint IDs |
| `updated_at` | Timestamp of last shadow update |

**Flow** (`app/ui/app.py`, in `_sync_tick` after getSyncData):

1. `diff_member_shadow(incoming_users, valid_member_ids)` → `{new, modified, deleted}`
2. For a **full refresh** (not `membersDeltaMode`): if shadow detects only a subset changed,
   `_delta_changed_ids` is narrowed to `{new ∪ modified}`. If nothing changed AND no deletes,
   `_delta_changed_ids = set()` (skip device push entirely this cycle).
3. `upsert_member_shadow(users)` updates the shadow for all incoming users.
4. `delete_member_shadow(deleted_ids)` removes stale shadow rows.

This means a full refresh that returns 2 000 members but only 1 changed will result in a
single-pin push to devices, not a 2 000-pin reconciliation.

---

## P7 — Device Content Mirror (Write-Through)

**Purpose**: Maintain an exact replica of what was last successfully pushed to each ZKTeco
device. Enables drift detection and visibility from the dashboard/API without re-reading
the device.

**Table** (`device_content_mirror` in SQLite):

| Column | Notes |
|--------|-------|
| `device_id, pin` | Composite PK |
| `full_name, card_no, door_bitmask, authorize_tz_id, fp_count` | What was pushed |
| `pushed_at` | ISO timestamp |
| `push_ok` | 0 = partial failure (auth incomplete) |

**Write-through points** (`app/core/device_sync.py`):

- **Successful push** (both batch Phase D and per-pin path): `upsert_device_mirror_pin(..., push_ok=True)`
- **Partial failure** (user pushed but auth incomplete): `upsert_device_mirror_pin(..., push_ok=False)`
- **Stale pin deleted**: `delete_device_mirror_pin(device_id, pin)`

---

## Data Flow Summary (After This Implementation)

```
Dashboard change (member card / FP / device)
  │
  ├─ POST /api/v1/...  (backend save)
  │    └─ JPA @PostPersist/Update → AccessSyncEvent row inserted
  │
  └─ POST localhost:8788/api/v2/sync/now  { entityType, entityId, operation, priority }
       │
       └─ MonClub Access app
            ├─ (P3 future): poll /changes endpoint for missed events
            ├─ diff_member_shadow → compute actual changed pins (P6)
            ├─ DeviceWorkerManager.dispatch_all(SyncJob)  ← non-blocking (P2)
            │    └─ DeviceWorker (per device daemon thread)
            │         ├─ connect to ZKTeco device
            │         ├─ _delete_pin_unconditional (P0 fix)
            │         ├─ SetDeviceData(user / authorize / template)
            │         ├─ upsert_device_mirror_pin (P7)
            │         └─ disconnect
            └─ after read: clear transaction table (P5)
```

---

## Files Changed

### Python (MonClub Access)
| File | Change |
|------|--------|
| `app/core/device_sync.py` | P0 fix, P1 policies, P2 worker integration, P7 mirror writes |
| `app/core/device_worker.py` | NEW — P2 DeviceWorker + DeviceWorkerManager |
| `app/core/device_attendance.py` | P5 auto-clear after read |
| `app/core/db.py` | P6 member_shadow + P7 device_content_mirror tables + helpers |
| `app/ui/app.py` | P6 shadow diff in sync tick, stop_workers on logout/destroy |

### Java (MonClub Backend)
| File | Change |
|------|--------|
| `Models/AccessSyncEvent.java` | NEW — CDC event entity |
| `Repositories/AccessSyncEventRepository.java` | NEW — cursor query + prune |
| `Configuration/SpringContextHolder.java` | NEW — static ApplicationContext holder |
| `Models/Listeners/AccessSyncEntityListener.java` | NEW — JPA listener |
| `Models/ActiveMembership.java` | +AccessSyncEntityListener |
| `Models/GymDevice.java` | +AccessSyncEntityListener |
| `Helper/ApiConstants.java` | +getGymAccessChanges constant |
| `Controllers/GymAccessController.java` | +getGymAccessChanges endpoint |
| `Services/DailyScheduleService.java` | +AccessSyncEvent 14-day prune |

### TypeScript (MonClub Dashboard)
| File | Change |
|------|--------|
| `sections/services/LocalAccessService.ts` | SyncHint interface + hint param on triggerLocalAccessSync |
| `sections/ActiveMembership/view/active-membership-form.tsx` | Pass HIGH priority hints on create/update |
| `sections/ActiveMembership/view/active-membership-fingerprints-dialog.tsx` | Pass HIGH priority hints on fp ops |
| `sections/GymDevices/view/gym-devices-view.tsx` | Add missing sync calls + NORMAL priority hints |

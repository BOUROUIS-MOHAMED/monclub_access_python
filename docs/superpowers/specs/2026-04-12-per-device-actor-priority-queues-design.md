# Per-Device Actor With Priority Queues Design

**Date:** 2026-04-12
**Status:** Draft
**Problem:** The current device runtime already has useful building blocks such as long-lived workers, targeted sync, and queued door-open commands. The remaining bottleneck is split ownership: urgent access work and heavy sync work still compete for the same device session, and some flows still pause one worker so another path can take over the socket. That ownership model is the wrong shape for the latency target.

---

## Overview

Move the device runtime to a **generic per-device actor model** for **all device types from day one**.

Each device gets one long-lived actor. That actor becomes the single normal owner of:

- device connection/session state
- RTLog polling
- tray and API open-door commands
- targeted member add, update, and delete work
- device configuration refresh
- background reconcile sync

The actor processes all work through a priority mailbox. Full sync is no longer one long blocking job. It is split into fixed-size chunks, and the actor re-checks the mailbox after every chunk so urgent work can jump ahead.

This is the downstream execution refactor that follows the fast-patch pipeline.

## Goals

- Enforce `one device, one owner` across the entire Access runtime.
- Apply the same actor model to every device type from the start.
- Eliminate the RTLog-worker pause and TCP handoff pattern.
- Guarantee that urgent door and access actions run before background sync work.
- Keep TOTP, tray open-door, and RTLog rescue working correctly.
- Allow fast-patch member updates to reach device actors immediately.
- Rebuild safely on app restart from local DB plus immediate reconcile.

## Non-Goals

- Persisting raw in-flight command queues across restart.
- Rewriting dashboard or backend contracts in this phase.
- Replacing the current access verification rules or TOTP logic.
- Solving latency by simply adding more threads without ownership boundaries.

## Current State

The current Access runtime already contains parts of the target model:

- per-device workers in `app/core/ultra_engine.py`
- a command queue for door-open operations
- targeted member sync support in `app/core/device_sync.py`
- sync orchestration in `app/ui/app.py`

The missing piece is unified ownership. Sync still pauses an RTLog worker and temporarily takes over the connection to perform pushes. That creates contention in the most latency-sensitive path. The current sync path also contains long-running batch phases that cannot yield to urgent device work.

## Chosen Design

Use a **generic per-device actor shell** for every device, with **device-family adapters** underneath it.

High-level runtime:

1. `ActorRegistry` starts one actor per active device
2. `CommandRouter` translates tray, local API, fast patch, RTLog, and reconcile events into actor messages
3. each `DeviceActor` owns its mailbox, connection state, health state, and current sync session
4. each actor uses a `DeviceAdapter` that knows how to talk to that specific device family
5. full sync runs as an interruptible chunked session, not as one large blocking operation

No other subsystem should normally open a second competing connection to the same device.

## Architecture

### DeviceActor

One long-lived thread or loop per device.

Responsibilities:

- own the device session
- manage mailbox execution
- poll RTLog where supported
- execute open-door commands
- run targeted member changes
- run chunked reconcile sync
- expose health and queue status

### DeviceAdapter

One adapter interface per device family.

Suggested adapter operations:

- `connect()`
- `disconnect()`
- `poll_rtlog_once()`
- `open_door()`
- `upsert_member()`
- `delete_member()`
- `apply_config()`
- `begin_sync_session()`
- `run_sync_chunk()`

The actor stays generic. Adapter differences live behind this interface.

### ActorMailbox

One mailbox per actor with:

- priority ordering
- message coalescing
- sync interruption points between chunks

### SyncSession

A per-device sync object that stores:

- sync type (`targeted` or `full`)
- current phase
- current cursor
- desired member set snapshot
- pending delete set
- pending upsert set
- pending template work
- config/apply checkpoint

The actor keeps the `SyncSession` in memory and resumes it after urgent work.

### ActorRegistry

Responsible for:

- building actors from the current device list
- restarting failed actors
- stopping removed devices
- replacing actors after device config changes

### CommandRouter

The only normal translation layer from external events to actor messages.

Producers include:

- tray and local open-door commands
- RTLog events
- fast-patch bundle application
- sync scheduler and reconcile timers
- device settings changes

## Message Types

Suggested actor messages:

- `OPEN_DOOR`
- `RTLOG_TICK`
- `RTLOG_REACTION`
- `MEMBER_UPSERT`
- `MEMBER_DELETE`
- `TARGETED_SYNC_START`
- `FULL_SYNC_START`
- `SYNC_NEXT_CHUNK`
- `DEVICE_CONFIG_REFRESH`
- `RECONNECT`
- `SHUTDOWN`

Not every adapter will implement RTLog in the same way, but the actor shell should be designed around this common message set.

## Effective Priority

Recommended priority order:

1. `OPEN_DOOR`
2. `RTLOG_REACTION`
3. `MEMBER_DELETE`
4. `MEMBER_UPSERT`
5. `DEVICE_CONFIG_REFRESH`
6. `TARGETED_SYNC_START`
7. `SYNC_NEXT_CHUNK`
8. `RTLOG_TICK`
9. `FULL_SYNC_START`
10. `RECONNECT`
11. `SHUTDOWN`

Why this order:

- open door is the most visible and time-sensitive action
- RTLog reaction is the live access path
- deletes and revokes are more urgent than adds
- config refresh should not leave the actor syncing against stale device assumptions
- targeted sync should beat full reconcile
- full reconcile remains important, but it is explicitly background work

## Mailbox Behavior

The mailbox must support:

- priority ordering
- coalescing of repeated member operations
- promotion of delete over older upsert
- collapse of repeated reconcile requests
- bounded queue metrics

Coalescing rules:

- latest `MEMBER_UPSERT(memberId)` replaces older queued upserts for that member
- `MEMBER_DELETE(memberId)` removes older queued upserts for the same member and wins
- repeated `FULL_SYNC_START` collapses to one pending reconcile request
- repeated `TARGETED_SYNC_START` merges member ids for the same device
- repeated `DEVICE_CONFIG_REFRESH` collapses to one latest config snapshot

Examples:

- ten updates for the same member should result in one latest upsert
- a queued upsert followed by a delete should end as delete
- multiple timer-based reconcile requests should become one reconcile session

## Fixed Chunking Policy

Full sync must be interruptible, but the chosen policy is **fixed per-operation chunk sizes**, not adaptive chunk sizing.

Recommended chunk sizes:

- delete chunk: `20` pins
- user upsert chunk: `25` users
- authorize chunk: `25` users
- template chunk: `5` users worth of templates

Rules:

- after **every chunk**, the actor returns to the mailbox and re-checks higher-priority work
- template work uses the smallest chunk because it is typically the slowest and least predictable
- if a user has many templates, that user's template work can end the chunk early

This means a large sync can still take a long time overall, but it cannot monopolize the actor for the entire duration.

## Sync Execution Model

Instead of one blocking “sync device now” operation:

1. actor receives `TARGETED_SYNC_START` or `FULL_SYNC_START`
2. actor builds a `SyncSession`
3. actor runs one chunk
4. actor re-checks mailbox
5. if a higher-priority message arrived, actor handles it immediately
6. actor later resumes the same `SyncSession` with `SYNC_NEXT_CHUNK`

This is the key latency guarantee:

- tray open-door does not wait behind a 1200-user reconcile
- fast-patch delete does not wait behind template-heavy sync
- RTLog rescue stays hot

## Sync Phases

Suggested phase order inside `SyncSession`:

1. device state snapshot / connect validation
2. stale delete phase
3. user phase
4. authorize phase
5. template phase
6. config/apply verification phase
7. final state commit / sync metadata update

Each phase advances through chunk-sized cursors.

## Actor State

Each actor should own a small focused state object:

- device metadata
- connection/session state
- adapter family/profile
- current mailbox summary
- current sync session and cursor
- last RTLog timestamp
- last successful door command timestamp
- last successful push timestamp
- retry and reconnect counters
- last error

This keeps device behavior local and debuggable.

## Interaction With Fast Patch

The fast-patch pipeline is the preferred producer for urgent membership changes.

After Access accepts a fast patch:

- it determines affected devices
- it sends `MEMBER_UPSERT` or `MEMBER_DELETE` to those device actors
- actors apply those changes immediately without waiting for a full reconcile cycle

Normal reconcile remains the safety net. If an actor later detects drift, a full sync can repair it.

## Restart And Recovery

The chosen restart model is:

- rebuild actor state from local DB
- immediately enqueue reconcile
- do **not** persist raw command queues

Startup sequence:

1. load local DB and sync metadata
2. rebuild device registry
3. start one actor per active device
4. enqueue `FULL_SYNC_START` for each active device

Reasons:

- no stale old open-door commands are replayed
- no raw command queue corruption risk
- local DB remains the durable desired-state source
- reconcile repairs device drift after restart

## Failure Handling

### Device offline

Actor keeps mailbox state in memory, retries connect with backoff, and exposes degraded state.

### Sync interrupted by urgent work

Actor stores `SyncSession` cursor and resumes later from the next chunk.

### Config changed mid-sync

Actor stops the current sync session, applies config refresh, and starts a new reconcile session.

### Delete arrives during sync

Delete wins over older queued upsert and is executed before more sync chunks continue.

### Actor crash or unhandled worker exception

Registry restarts the actor, rebuilds state from local DB, and enqueues reconcile.

### Access restart

Actors are rebuilt from device list, then reconcile from local DB.

## Connection Strategy

The actor is the only normal reader and writer for its device session.

Instead of:

- worker owns socket
- sync pauses worker
- second path takes connection
- worker resumes later

The target state is:

- actor owns session
- actor interleaves RTLog polling and mailbox work
- actor itself reconnects if needed
- no second subsystem steals the device connection

If a device family truly requires reconnects, the reconnect is still initiated by the actor through its adapter.

## Health And Status Model

Each actor should expose:

- `state`: `starting`, `ready`, `syncing`, `degraded`, `offline`, `stopped`
- `connected`
- `queueDepth`
- `highestPendingPriority`
- `lastRTLogAt`
- `lastDoorCommandAt`
- `lastSuccessfulSyncAt`
- `syncCursor`
- `lastError`

This is required so the system never becomes a silent black hole.

## Observability

Add actor-level metrics and logs for:

- queue depth by priority
- enqueue-to-start latency
- per-chunk execution duration
- reconnect count
- sync coalescing count
- stale member messages dropped
- sync defer count
- RTLog idle and active time

This is how we verify whether actorization really improves contention.

## Testing

### Unit

- priority ordering
- delete dominates older upsert for same member
- full-sync collapse behavior
- targeted-sync merge behavior
- sync cursor resumes correctly after interruption

### Integration

- open-door command is not blocked by pending sync chunks
- fast-patch delete reaches actor before background reconcile resumes
- config refresh interrupts sync and starts new reconcile
- actor reconnect preserves mailbox state

### Regression

- TOTP-driven open-door path still works
- tray open-door still works
- RTLog processing still feeds existing access feedback flows
- fast-patch member change still becomes targeted device work

## Files Likely To Change

### monclub_access_python

- `app/core/ultra_engine.py`
- `app/core/device_sync.py`
- `app/ui/app.py`

Likely new focused modules:

- `app/core/device_actor.py`
- `app/core/device_adapter.py`
- `app/core/device_mailbox.py`
- `app/core/device_sync_session.py`
- `app/core/device_registry.py`

Exact filenames can follow existing repo style, but these responsibilities should be split into focused modules rather than expanding `ultra_engine.py` further.

## Rollout Order

1. keep fast patch pipeline as the upstream freshness path
2. introduce generic actor shell and mailbox
3. route open-door commands through actors first
4. route targeted fast-patch member work through actors
5. move reconcile sync to chunked actor-owned sessions
6. remove socket handoff and pause-for-sync behavior
7. validate latency and failure behavior across all device families

## Relationship To Fast Patch

This design is intentionally downstream from:

`docs/superpowers/specs/2026-04-12-fast-patch-pipeline-design.md`

Fast patch solves freshness first.
The actor model solves device-side execution, connection ownership, interruption, and queue priority second.

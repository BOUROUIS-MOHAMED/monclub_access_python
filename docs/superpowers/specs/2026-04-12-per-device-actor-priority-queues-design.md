# Per-Device Actor With Priority Queues Design

**Date:** 2026-04-12
**Status:** Draft
**Problem:** The current ULTRA flow already supports targeted sync and a long-lived RTLog worker, but sync still pauses the worker and temporarily hands device ownership to another path for pushes. That handoff creates unnecessary contention in the exact part of the system where low latency matters most.

---

## Overview

Move device ownership toward a per-device actor model.

Each device actor becomes the single owner of:

- the live device connection
- RTLog polling
- open-door commands from tray or access logic
- targeted member push or delete work
- periodic reconcile sync work

The actor processes those actions through a priority queue so urgent door and access actions are never trapped behind bulk sync work.

This is the follow-up track after fast patch pipeline delivery.

## Goals

- Eliminate the current RTLog-worker pause and TCP handoff pattern for ULTRA devices.
- Make urgent commands execute ahead of bulk sync work.
- Preserve correct TOTP and tray open-door behavior.
- Reduce the time between a local membership decision and actual device update.
- Keep one clear owner per device connection.

## Non-Goals

- Rewriting every sync subsystem in one step.
- Changing dashboard or backend contracts as part of this phase.
- Replacing existing access verification logic.
- Adding generic thread count without clear ownership rules.

## Current State

The Access app already has important pieces of this design:

- a long-lived ULTRA worker for RTLog
- a scheduler that can accumulate `changed_ids`
- a command queue for some open-door actions
- device sync code that can accept targeted member changes

The missing piece is unified ownership. During sync, the scheduler still pauses the RTLog worker so another path can take the socket and push updates. That means the most latency-sensitive path and the most I/O-heavy path still compete.

## Chosen Design

Use **one actor per device** with a strict priority queue and a single connection owner.

High-level loop:

1. actor holds or manages the device connection
2. actor polls RTLog with short cadence
3. actor drains any queued higher-priority actions between poll windows
4. actor performs small targeted writes immediately
5. actor performs background reconcile work only when no higher-priority work is pending

No other component should open a second competing connection to the same device during normal operation.

## Message Types

Suggested actor messages:

- `OPEN_DOOR`
- `PROCESS_RTLOG_RESULT`
- `FAST_PATCH_UPSERT_MEMBER`
- `FAST_PATCH_DELETE_MEMBER`
- `TARGETED_SYNC`
- `FULL_RECONCILE_SYNC`
- `DEVICE_CONFIG_REFRESH`
- `FORCE_RESYNC`
- `SHUTDOWN`

Not every message type needs to exist on day one, but the ownership model should be designed for this set.

## Priority Model

Recommended priority order:

1. `OPEN_DOOR`
2. `PROCESS_RTLOG_RESULT`
3. `FAST_PATCH_DELETE_MEMBER`
4. `FAST_PATCH_UPSERT_MEMBER`
5. `TARGETED_SYNC`
6. `FULL_RECONCILE_SYNC`
7. `DEVICE_CONFIG_REFRESH`

Why this order:

- open door is the most user-visible and time-sensitive action
- RTLog processing is the live access path and must remain hot
- deletes and revokes matter more than adds because stale access is a security problem
- targeted sync should win over full sync
- full reconcile should remain the background safety net

## Queue Behavior

The queue should support:

- message coalescing for repeated member updates
- promotion of deletes over older queued upserts for the same member
- collapsing repeated full-sync requests into one pending reconcile
- bounded backlog metrics so the app can expose queue pressure

Examples:

- ten updates for the same member should end as one latest upsert
- a queued upsert followed by a delete for the same member should end as delete
- multiple timer-based reconcile requests should collapse into one

## Actor State

Each device actor should own a small state object:

- device metadata
- connection/session state
- last-known firmware profile
- last sync fingerprint or hash
- pending queue summary
- last RTLog timestamp
- last successful push timestamp
- health and retry counters

This keeps device behavior local and makes debugging easier.

## Interaction With Fast Patch

The fast-patch pipeline is the preferred producer for urgent member updates.

After local Access accepts a fast patch:

- it determines affected devices
- it sends targeted actor messages only to those devices
- the actor applies the member add, update, or delete without waiting for a full sync cycle

Normal reconcile still exists. If the actor sees a mismatch, a later full reconcile can repair it.

## ULTRA First, Then Broader Adoption

This design should start with ULTRA devices because that is where RTLog latency and TCP ownership matter most.

Suggested rollout:

1. keep current non-ULTRA sync path unchanged
2. actorize ULTRA ownership first
3. prove door latency and targeted push behavior improve
4. decide later whether non-ULTRA devices should use the same actor shell or keep the existing engine

That keeps the scope controlled while solving the bottleneck that matters most.

## Connection Strategy

The actor should be the only normal writer and reader for its device connection.

Instead of:

- RTLog worker owns the socket
- sync path pauses worker
- sync path opens or reuses another connection
- worker resumes later

The target state is:

- actor owns the socket
- actor interleaves read windows and write commands
- actor serializes all device interaction in one place

If a device or SDK limitation forces occasional reconnect, that reconnect should still be initiated by the actor itself, not by a second owner.

## Failure Handling

### Device temporarily offline

Actor keeps queue state, retries with backoff, and preserves higher-priority messages.

### Repeated push failure for one member

Actor records failure, exposes it in status, and leaves full reconcile available as repair.

### Queue overload

Actor coalesces member messages and collapses full syncs so the queue does not grow without bound.

### Connection reset during RTLog load

Actor reconnects and resumes ownership without requiring another subsystem to take over.

## Observability

Add actor-level metrics and logs for:

- queue depth by priority
- enqueue-to-start latency
- command execution duration
- reconnect count
- sync coalescing count
- dropped stale member messages
- RTLog idle and active time

This is required so we can tell whether the actor model is actually reducing contention.

## Testing

### Unit

- queue coalescing and priority ordering
- delete dominates earlier upsert for same member
- full sync collapse behavior

### Integration

- open-door command is not blocked by pending full sync
- fast-patch delete reaches device actor before background reconcile
- actor reconnect logic preserves pending work

### Regression

- TOTP-driven open-door path still works
- tray open-door still works
- RTLog processing still feeds existing access feedback flows

## Files Likely To Change

### monclub_access_python

- `app/core/ultra_engine.py`
- `app/core/device_sync.py`
- any worker or scheduler split used by ULTRA polling
- sync orchestration in `app/ui/app.py`

Additional small state or queue helpers may deserve their own focused modules instead of expanding `ultra_engine.py` further.

## Rollout Order

1. ship fast patch pipeline first
2. measure remaining `local cache updated -> device actually updated` latency
3. actorize ULTRA device ownership
4. remove the worker-pause handoff only after the actor path is proven stable
5. evaluate whether the same model should expand to the rest of the device stack

## Relationship To Fast Patch

This design is intentionally downstream from:

`docs/superpowers/specs/2026-04-12-fast-patch-pipeline-design.md`

Fast patch solves freshness first. The actor model solves device-side execution and connection ownership second.

# Fast Patch Pipeline Design

**Date:** 2026-04-12
**Status:** Draft
**Problem:** Access currently learns about dashboard changes through `sync_now` hints and a later backend pull. That is safe, but it leaves avoidable delay between a successful dashboard save and the moment the local Access app, TOTP/card verification, and ZKTeco device push path reflect the new state.

---

## Overview

Add a canonical fast-patch pipeline for all access-relevant dashboard changes.

After a successful dashboard mutation, the dashboard asks the backend to resolve a canonical `AccessPatchBundle`, forwards that bundle to the local Access app over localhost, and the Access app applies it immediately to local storage, hot in-memory state, and targeted device actions. The existing backend sync remains the mandatory reconcile and repair path.

This design is intentionally a **final-product design**, not a narrow `v1` subset. The target scope from day one includes:

- `ACTIVE_MEMBERSHIP`
- `fingerprint` changes, folded into membership access patches
- `GYM_DEVICE`
- `SETTINGS`
- `CREDENTIALS`
- `INFRASTRUCTURES`
- `MEMBERSHIP_TYPE`

## Goals

- Reduce `dashboard save -> local Access state updated` latency from sync-cycle scale to request scale.
- Let Access react immediately after a successful backend mutation without waiting for the next pull sync.
- Keep backend as the only source of truth.
- Preserve the existing reconcile sync as a safety net for drift, missed delivery, or out-of-order updates.
- Keep TOTP, card verification, tray commands, and device push behavior correct.
- Support all access-relevant dashboard change types through one unified transport.

## Non-Goals

- Replacing the current backend sync pipeline.
- Making the dashboard authoritative.
- Using browser form DTOs as direct Access payloads.
- Solving the per-device actor refactor in this spec.
- Adding websocket between dashboard UI and Access just for this feature.

## Current State

Today the dashboard can only send a best-effort localhost sync hint through `POST /api/v2/sync/now`.

Current path:

1. Dashboard saves a member, fingerprint, device, or configuration change to backend.
2. Dashboard posts a small hint to local Access.
3. Access schedules sync.
4. Access later pulls `get_sync_data` from backend.
5. Access updates local cache.
6. Access computes affected members or devices and may trigger targeted push.

This already works, but Access never receives the canonical changed projection directly.

## Considered Approaches

### 1. Raw dashboard fan-out

Dashboard sends its own changed models directly to Access and Access interprets them.

Pros:

- fastest to wire

Cons:

- duplicates backend rules in the browser
- fragile for eligibility, deletes, and cross-entity fallout
- becomes messy once settings, credentials, infrastructures, and membership types are included

### 2. Canonical backend patch bundle forwarded by dashboard

Dashboard saves normally, then asks backend for a canonical access patch bundle and forwards it to Access.

Pros:

- backend stays canonical
- one transport can support all change types
- Access gets explicit impact hints instead of guessing
- compatible with existing sync fallback

Cons:

- requires new resolver contract on backend
- needs patch apply pipeline in Access

### 3. Direct backend-to-Access event stream

Backend emits canonical access events and Access listens directly.

Pros:

- clean long-term architecture

Cons:

- heavier operationally
- slower to ship than the current need

## Chosen Design

Use **canonical backend patch bundles forwarded by dashboard, with Access-side transactional apply and background reconcile**.

High-level flow:

1. Dashboard performs the normal backend mutation.
2. After backend success, dashboard calls a generic backend patch resolver.
3. Backend returns a canonical `AccessPatchBundle`.
4. Dashboard forwards the bundle to local Access over localhost.
5. Access validates, dedupes, and applies the bundle transactionally.
6. Access invalidates hot local caches and executes targeted runtime actions.
7. Access schedules one background reconcile sync for the bundle.
8. If reconcile disagrees later, backend state wins and Access corrects itself.

This keeps the dashboard fast without turning it into a source of truth.

## Supported Change Scope

Fast patch must support these change origins:

- `ACTIVE_MEMBERSHIP`
- `FINGERPRINT`
- `GYM_DEVICE`
- `SETTINGS`
- `CREDENTIALS`
- `INFRASTRUCTURES`
- `MEMBERSHIP_TYPE`

Normalization rules:

- `FINGERPRINT` does not travel as a standalone local patch item. Backend resolves it into an `ACTIVE_MEMBERSHIP` access patch because fingerprints belong to the membership access projection.
- `SETTINGS`, `CREDENTIALS`, `INFRASTRUCTURES`, and `MEMBERSHIP_TYPE` usually travel as section patches, not fake entity patches.

## Canonical Backend Contract

Dashboard resolves one generic bundle after any successful mutation:

`POST /api/v1/manager/gym/access/v1/patch-bundles/resolve`

Suggested request:

```json
{
  "schemaVersion": 1,
  "changeRef": {
    "entityType": "ACTIVE_MEMBERSHIP",
    "entityId": 1234,
    "operation": "UPDATE"
  },
  "source": "DASHBOARD",
  "requestedAt": "2026-04-12T12:00:00Z"
}
```

Suggested response:

```json
{
  "schemaVersion": 1,
  "bundleId": "4f6f39d7-b173-4d1d-a6ee-9e8f7261f2cf",
  "gymId": 42,
  "generatedAt": "2026-04-12T12:00:01Z",
  "items": [
    {
      "itemId": "deab0fc2-cf08-440b-ac50-a7f2ac8d8552",
      "kind": "ENTITY_UPSERT",
      "entityType": "ACTIVE_MEMBERSHIP",
      "entityId": 1234,
      "revision": "2026-04-12T12:00:01Z",
      "payload": {
        "activeMembershipId": 1234,
        "membershipId": 55,
        "userId": 88,
        "name": "Mohamed Example",
        "phone": "...",
        "email": "...",
        "startDate": "2026-04-01",
        "endDate": "2026-05-01",
        "card": "100234",
        "secondCard": null,
        "userImage": "...",
        "fingerprints": []
      },
      "impact": {
        "affectedMemberIds": [1234],
        "affectedDeviceIds": [8, 9],
        "requiresDeviceRescope": false,
        "requiresServiceRebind": false,
        "requiresControlledRestart": false
      }
    }
  ],
  "requiresReconcile": true
}
```

Supported patch item kinds:

- `ENTITY_UPSERT`
- `ENTITY_DELETE`
- `SECTION_REPLACE`
- `SECTION_INVALIDATE`

Key rules:

- Backend owns patch payload shape and impact hints.
- Dashboard never fabricates patch payloads.
- `bundleId` is idempotency key.
- `revision` is required for stale-item rejection.
- A single bundle may contain mixed items, for example device, settings, and membership-type fallout from one dashboard action.

## Patch Item Semantics

### `ACTIVE_MEMBERSHIP`

- `ENTITY_UPSERT` when the member should exist locally
- `ENTITY_DELETE` when the member must disappear from local Access
- includes fingerprint data as part of the canonical membership projection

### `GYM_DEVICE`

- `ENTITY_UPSERT` or `ENTITY_DELETE`
- payload includes access mode, scope, connection fields, and door presets needed by local runtime

### `SETTINGS`

- usually `SECTION_REPLACE`
- payload is the canonical access settings snapshot

### `CREDENTIALS`

- usually `SECTION_REPLACE`
- payload is the canonical local QR/TOTP credential snapshot

### `INFRASTRUCTURES`

- usually `SECTION_REPLACE`
- payload is the canonical infrastructure snapshot used by local access features

### `MEMBERSHIP_TYPE`

- usually `SECTION_REPLACE`
- payload is the canonical membership-type list that influences device membership filtering

## Dashboard Responsibilities

Dashboard should centralize this behavior in one service, not scatter it across pages.

Recommended service responsibility:

- accept a simple `changeRef`
- call backend bundle resolver
- forward the bundle to local Access
- trigger fallback reconcile hint when needed
- swallow localhost delivery failures so UI save never fails because Access is offline

Dashboard sequencing:

1. backend mutation success
2. bundle resolve
3. local Access bundle post
4. fallback `sync_now` hint

Dashboard should remain best-effort toward local Access.

## Local Access Contract

Add one generic localhost receiver:

`POST /api/v2/sync/fast-patch-bundle`

Access applies the bundle through a dedicated fast-patch pipeline, not by overloading `sync_now`.

Receiver responsibilities:

1. require the existing local API token
2. validate schema version, `gymId`, and structure
3. reject duplicate bundles by `bundleId`
4. reject stale items by patch key and `revision`
5. pass the bundle into one transactional apply path
6. execute aggregated runtime actions after commit
7. schedule one reconcile sync for the bundle

## Access Internal Apply Pipeline

Recommended internal split:

- local API receiver in `app/api/local_access_api_v2.py`
- transactional DB applier in `app/core/db.py`
- runtime action executor in `app/ui/app.py`

Apply sequence:

1. receive bundle
2. validate token and payload
3. check processed bundle ledger
4. start one SQLite transaction
5. apply each item only to its owned normalized tables
6. save per-item latest revisions
7. commit transaction
8. invalidate hot caches immediately
9. execute runtime actions
10. trigger one background reconcile

Fast patch must update only the affected normalized tables. It should not rewrite the whole sync cache payload for every bundle.

## Runtime Action Classes

Every applied patch item should map into one or more action classes:

- `CACHE_ONLY`
- `TARGETED_MEMBER_PUSH`
- `TARGETED_DEVICE_RELOAD`
- `SERVICE_REBIND`
- `CONTROLLED_RUNTIME_RESTART`
- `BACKGROUND_RECONCILE`

This lets Access react correctly without treating all patch types the same way.

## Impact Matrix

| Patch type | Patch shape | Immediate local apply | Immediate runtime effect |
|---|---|---|---|
| `ACTIVE_MEMBERSHIP` | `ENTITY_UPSERT` / `ENTITY_DELETE` | update or remove cached member and fingerprints | `TARGETED_MEMBER_PUSH` for affected devices, then `BACKGROUND_RECONCILE` |
| `FINGERPRINT` | resolved as `ACTIVE_MEMBERSHIP` patch | same as membership | same as membership |
| `GYM_DEVICE` | `ENTITY_UPSERT` / `ENTITY_DELETE` | update or remove cached device and door presets | `TARGETED_DEVICE_RELOAD` for affected device, optional targeted sync, then reconcile |
| `CREDENTIALS` | `SECTION_REPLACE` | replace local credential snapshot | invalidate local QR/TOTP state immediately, then reconcile |
| `SETTINGS` | `SECTION_REPLACE` | replace normalized settings snapshot | split by field into cache-only, service rebind, or controlled restart |
| `INFRASTRUCTURES` | `SECTION_REPLACE` | replace infrastructure snapshot | usually cache-only, unless backend impact says device work is needed |
| `MEMBERSHIP_TYPE` | `SECTION_REPLACE` | replace membership-type snapshot | recompute device membership scope; targeted device work only if impact requires it |

## Settings-Specific Runtime Rules

`SETTINGS` are not all equal.

### `SERVICE_REBIND`

These settings can change local API binding and should rebind services immediately:

- `accessServerEnabled`
- `accessServerPort`

### `CONTROLLED_RUNTIME_RESTART`

These settings affect long-lived worker topology and should trigger controlled rebuild or restart behavior:

- `decisionWorkers`
- `notificationServiceEnabled`
- `historyServiceEnabled`

### `LIVE INVALIDATION`

These settings should update immediately after cache invalidation without blanket device push:

- TOTP and RFID behavior knobs
- popup flags and popup defaults
- `defaultAuthorizeDoorId`
- `sdkReadInitialBytes`
- timing and queue sizing settings that are read dynamically by local runtime

## Hot Cache Invalidation

Fast patch is only fast if Access invalidates hot in-memory state immediately after commit.

Required invalidation targets:

- `load_sync_cache()` TTL cache
- decision-service local credential and user state caches
- ULTRA member and credential cache

This matters most for:

- membership changes
- fingerprint changes
- credential changes

Without immediate invalidation, a patch may be written to SQLite but still miss the next few local verification calls.

## Dedupe and Revision State

Add two small pieces of local state:

### Processed bundle ledger

Tracks:

- `bundleId`
- `generatedAt`
- `appliedAt`

Purpose:

- strict idempotency for bundle replay

### Latest revision ledger

Tracks latest revision by patch key, for example:

- `ACTIVE_MEMBERSHIP:1234`
- `GYM_DEVICE:9`
- `SECTION:CREDENTIALS`
- `SECTION:SETTINGS`

Purpose:

- reject out-of-order or stale items even when bundle IDs differ

## Security

Fast patch must reuse current localhost protections:

- loopback-only bind
- existing local API token

The new endpoint should not weaken that model.

Additional security rules:

- only backend-confirmed bundles are accepted
- dashboard form DTOs are never accepted as access patches
- bundle apply is transactional
- runtime action failure must not roll back already-committed canonical data

## Failure Handling

### Backend mutation succeeds, bundle resolve fails

Dashboard save remains successful. Fallback `sync_now` reconcile repairs later.

### Bundle resolve succeeds, local Access is offline

Dashboard save remains successful. Fallback reconcile repairs later.

### Bundle apply succeeds, device runtime action fails

Canonical local data remains updated. Access exposes degraded status, retries targeted action as needed, and keeps reconcile pending.

### Controlled restart or rebind fails

Keep committed data, surface error status locally, and retry or reconcile. Do not roll back canonical local data.

### Duplicate bundle received

Ignore safely by `bundleId`.

### Out-of-order bundle received

Drop stale items by revision and still schedule reconcile if needed.

## Observability

Add first-class timestamps and logs for the two latency paths that matter.

### Dashboard change to device update

Track:

1. `mutation_saved_at`
2. `bundle_resolved_at`
3. `bundle_forwarded_at`
4. `bundle_received_at`
5. `bundle_applied_at`
6. `runtime_action_started_at`
7. `device_push_started_at`
8. `device_push_finished_at`
9. `reconcile_finished_at`

### QR scan to door open

Track:

1. `rtlog_seen_at`
2. `verification_started_at`
3. `verification_finished_at`
4. `door_command_started_at`
5. `door_command_finished_at`

Also log:

- fast patch accepted
- duplicate bundle ignored
- stale item ignored
- cache invalidation done
- targeted runtime actions chosen
- reconcile scheduled
- reconcile mismatch repaired

## Testing

### Backend

- resolver returns correct bundle shape for every supported entity type
- fingerprints resolve into membership patches
- mixed bundles carry correct impact hints

### Dashboard

- one dispatch service handles all mutation success paths
- local Access outage does not fail dashboard save

### Access

- transactional bundle apply
- duplicate bundle ignored
- stale item rejected
- hot caches invalidated immediately
- runtime actions routed correctly by patch type

### End-to-End

- membership freeze or unfreeze updates local Access before next sync cycle
- fingerprint delete removes local membership template plan immediately
- device change updates local device routing and reload behavior
- credential change updates local TOTP verification behavior immediately
- settings rebind or restart path works safely
- infrastructure and membership-type changes trigger only the needed downstream work

### Regression

- TOTP rescue still works
- tray open-door still works
- normal sync still reconciles correctly
- ULTRA targeted sync still works
- local API health and token checks still work

## Acceptance Criteria

- Any supported dashboard access change can resolve to a canonical patch bundle.
- Access can apply supported bundle items without waiting for the next normal sync cycle.
- Local TOTP and card verification reflect patch changes immediately after apply.
- Device work is targeted by impact, not blanket full-push by default.
- Background reconcile remains enabled and authoritative.
- Fast patch failure never breaks dashboard save success.
- Logs make both critical latency paths measurable end to end.

## Files Likely To Change

### `monclub_backend`

- `Controllers/GymAccessController.java`
- `Controllers/GymDeviceController.java`
- `Controllers/GymAccessSoftwareSettingsController.java`
- `Controllers/GymAccessCredentialController.java`
- `Controllers/GymInfrastructureController.java`
- `Controllers/MembershipController.java`
- new patch resolver DTOs and service classes under the access layer

### `mon_club_dashboard`

- `src/sections/services/LocalAccessService.ts`
- centralized new service for resolve-and-dispatch behavior
- mutation success call sites for memberships, fingerprints, devices, settings, credentials, infrastructures, and membership types

### `monclub_access_python`

- `app/api/local_access_api_v2.py`
- `app/core/db.py`
- `app/ui/app.py`
- selected cache invalidation points in local verification and ULTRA runtime

## Relationship To Device Actor Design

This design solves freshness and immediate local reaction first.

It intentionally does **not** include the deeper single-owner per-device refactor. That follow-up architecture remains documented in:

`docs/superpowers/specs/2026-04-12-per-device-actor-priority-queues-design.md`

The two designs are complementary:

- fast patch improves `dashboard change -> local Access updated`
- per-device actor improves `local Access updated -> device actually updated`

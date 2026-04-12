# Fast Patch Pipeline Design

**Date:** 2026-04-12
**Status:** Draft
**Problem:** A member or fingerprint change currently reaches the local Access app through a `sync_now` hint, then waits for the next backend pull/reconcile cycle. That keeps the system safe, but it leaves avoidable delay between a dashboard save and the moment the changed member is usable at the turnstile.

---

## Overview

Add a fast-path pipeline that delivers a backend-confirmed membership access patch from dashboard to the local Access app immediately after a successful dashboard mutation.

The fast patch does **not** replace normal sync. It short-circuits the slow path for fresh changes, while the existing backend sync remains the canonical reconcile and repair loop.

This is the first implementation target because it gives the biggest latency win with the smallest architectural blast radius.

## Goals

- Reduce `dashboard save -> local access cache updated` latency from sync-cycle scale to request scale.
- Let Access decide immediately whether a changed member must be pushed to one or more ZKTeco devices.
- Keep backend as the only source of truth.
- Preserve the current `sync_now` fallback so the system self-heals after missed local patches.
- Cover the highest-value path first: active membership and fingerprint changes.

## Non-Goals

- Replacing the existing periodic or triggered sync pipeline.
- Making the dashboard itself authoritative.
- Solving the ULTRA TCP ownership problem in this phase.
- Refactoring every device flow at the same time.
- Introducing UI websocket transport just for this feature.

## Current State

Today the dashboard can only send a best-effort sync hint to local Access through `POST /api/v2/sync/now`.

Current path:

1. Dashboard saves a member, fingerprint, or device change to backend.
2. Dashboard calls local Access `sync_now` with a small hint payload.
3. Access schedules a sync and later calls the backend sync endpoint.
4. Access updates local cache.
5. Access computes changed IDs and may trigger targeted device push.

This already works and is safe, but it still waits on a backend pull cycle. The local Access app never receives the changed canonical model directly.

## Chosen Design

Use **Fast Patch + Canonical Reconcile**.

Flow:

1. Dashboard performs the normal backend mutation.
2. After backend success, dashboard requests a dedicated canonical access patch for that membership.
3. Dashboard sends that patch to the local Access app over localhost.
4. Access applies the patch to local cache and in-memory indexes immediately.
5. Access enqueues targeted device push decisions immediately.
6. Access also triggers the existing sync path as a fallback reconcile.
7. If reconcile disagrees later, backend data wins and Access corrects local state.

This keeps the dashboard out of the source-of-truth role while still using it as the fastest transport already present in the user flow.

## Why This Approach

Three candidate approaches exist:

1. Dashboard forwards raw form data directly to Access.
This is the fastest to wire but the weakest design. It duplicates access rules in the browser and risks stale or partial payloads.

2. Dashboard fetches a dedicated backend-confirmed access patch after mutation, then forwards it to Access.
This is the recommended phase-1 design. It is explicit, canonical, and still far faster than waiting for full sync.

3. Every backend mutation response embeds the access patch directly.
This is also valid, but it is more invasive because it spreads access-specific payload shaping across multiple mutation endpoints.

## Phase-1 Scope

Phase 1 covers `ACTIVE_MEMBERSHIP` fast patches only.

That includes:

- member eligibility changes
- freeze or unfreeze effects
- card changes
- start or end date changes
- image changes if they affect access payload
- fingerprint add, update, or remove, because fingerprints already belong to the member access projection

`GYM_DEVICE` fast patches are intentionally deferred. Device-change sync can keep using the current hint-driven reconcile path for now.

## Canonical Patch Contract

The patch is a backend-owned projection, not a dashboard-owned DTO.

Suggested envelope:

```json
{
  "schemaVersion": 1,
  "gymId": 42,
  "entityType": "ACTIVE_MEMBERSHIP",
  "entityId": 1234,
  "operation": "UPSERT",
  "canonicalUpdatedAt": "2026-04-12T11:03:22Z",
  "source": "BACKEND_CONFIRMED",
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
  }
}
```

For a member that must no longer exist in Access, the backend returns a remove-style patch:

```json
{
  "schemaVersion": 1,
  "gymId": 42,
  "entityType": "ACTIVE_MEMBERSHIP",
  "entityId": 1234,
  "operation": "DELETE",
  "canonicalUpdatedAt": "2026-04-12T11:03:22Z",
  "source": "BACKEND_CONFIRMED",
  "reason": "NO_LONGER_ELIGIBLE",
  "payload": null
}
```

Important rules:

- Access accepts only backend-confirmed patches.
- `canonicalUpdatedAt` or an equivalent revision field is mandatory for dedupe and stale-patch rejection.
- The payload shape should match the access sync member projection as closely as possible, so Access can reuse existing cache and push logic.
- Eligibility is decided by backend. Access does not re-implement business eligibility rules from dashboard forms.

## Backend Changes

Add a dedicated read endpoint that returns the access projection for one active membership after a successful mutation.

Suggested shape:

`GET /api/v1/manager/gym/access/v1/patch/active-membership/{id}`

Behavior:

- If the membership is valid for Access, return an `UPSERT` patch with the canonical member payload.
- If the membership exists but should no longer appear in Access, return a `DELETE` patch.
- If the ID is unknown or out of gym scope, return `404` or an explicit empty/delete response depending on what makes dashboard handling simpler.

Why a dedicated endpoint in phase 1:

- keeps the patch projection centralized in one backend place
- avoids touching every mutation response shape immediately
- gives dashboard a clear "fetch canonical patch, then forward" contract

The backend already has useful building blocks for this:

- the sync endpoint already knows how to build member access DTOs
- `AccessSyncEntityListener` already records active-membership changes for reconcile and repair
- delta sync already computes member-level canonical access projections

## Dashboard Changes

After a successful member or fingerprint mutation:

1. call the backend patch endpoint for the affected active membership
2. post the returned patch to local Access
3. still send the existing `sync_now` hint as fallback

This should remain best-effort and non-blocking for the UI. A local Access outage must not break dashboard save success.

Suggested local call:

`POST /api/v2/sync/fast-patch`

Dashboard sequencing rule:

- backend mutation success first
- canonical patch fetch second
- local Access post third
- reconcile hint last

## Access Changes

Add a new local API endpoint to receive fast patches:

`POST /api/v2/sync/fast-patch`

On receipt, Access should:

1. validate schema and gym scope
2. reject stale or duplicate patches using `canonicalUpdatedAt` or equivalent revision
3. apply the patch to local cache storage
4. update the in-memory member access view used by fast verification paths
5. compute affected devices
6. enqueue targeted push work
7. trigger the existing sync reconcile in the background

Phase-1 patch application rules:

- `UPSERT`: insert or replace the cached member and associated fingerprints
- `DELETE`: remove the member from local access cache and mark it for device deletion
- local state change should happen before background reconcile
- background reconcile must not overwrite newer local patch state with an older patch

## Device Push Decision

Fast patch does not mean "push to every device."

Access should decide push scope using the same membership-to-device rules already used during sync. The immediate output of a fast patch should be:

- `changed_ids` for candidate member upserts
- `removed_ids` for candidate device deletions
- a narrowed set of affected devices where possible

Deletes and revocations must be treated as higher urgency than normal adds or updates.

## Reconcile and Self-Healing

The existing sync path remains mandatory.

After every accepted fast patch, Access schedules a background reconcile using the current hint mechanism. That covers:

- missed localhost delivery
- duplicate or out-of-order browser events
- backend-side changes that happened outside dashboard
- partial local cache corruption
- future schema drift

If reconcile disagrees with the fast patch, backend state wins.

## Failure Handling

### Backend mutation succeeds, local Access post fails

Dashboard save stays successful. The fallback `sync_now` reconcile eventually repairs Access.

### Dashboard fetches patch, but patch is stale by the time it reaches Access

Access rejects it using `canonicalUpdatedAt` or revision comparison and still runs reconcile.

### Dashboard sends duplicate fast patches

Access dedupes them and should not re-push unchanged device state.

### Membership becomes ineligible

Backend emits `DELETE`, Access removes local cache entry immediately, and device deletion is queued with high priority.

## Observability

Add explicit logs and counters for:

- fast patch received
- fast patch accepted
- fast patch rejected as stale
- fast patch apply duration
- device targets selected from patch
- reconcile triggered after patch
- reconcile mismatch repaired after patch

This is needed so we can prove the feature is reducing real latency instead of only adding another code path.

## Testing

### Backend

- canonical patch endpoint returns correct `UPSERT` payload
- frozen, expired, deleted, or out-of-scope members return `DELETE`
- fingerprints are included in the canonical member payload

### Dashboard

- save success does not depend on local Access availability
- successful mutation triggers patch fetch, local post, then fallback sync hint

### Access

- accepted patch updates SQLite cache and in-memory access view immediately
- stale or duplicate patch is ignored safely
- delete patch removes local member and produces device delete intent
- reconcile after patch keeps state correct

### End-to-End

- membership freeze or unfreeze reaches local Access before the next normal sync cycle
- fingerprint delete removes the member template from device push plan quickly

## Files Likely To Change

### monclub_backend

- `Controllers/GymAccessController.java`
- response DTOs or new patch DTO classes under the access API layer
- possibly a small dedicated service for access patch projection

### mon_club_dashboard

- `src/sections/services/LocalAccessService.ts`
- member and fingerprint mutation call sites

### monclub_access_python

- `app/api/local_access_api_v2.py`
- local cache write helpers in `app/core/db.py`
- sync/app orchestration in `app/ui/app.py`
- device targeting helpers in the sync layer

## Rollout Order

1. implement backend canonical patch endpoint
2. implement local Access `fast-patch` receiver
3. wire dashboard mutation flows to fetch and forward the patch
4. keep `sync_now` reconcile enabled from day one
5. measure latency before narrowing more scope or removing any existing safety net

## Deferred Follow-Up

The per-device actor model is intentionally not part of this first implementation. That design is captured separately in:

`docs/superpowers/specs/2026-04-12-per-device-actor-priority-queues-design.md`

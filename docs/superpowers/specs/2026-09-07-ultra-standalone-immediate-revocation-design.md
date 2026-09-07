# ULTRA Standalone Immediate Revocation Design

## Objective

When automatic synchronization is enabled, every authoritative membership revocation must be sent immediately to each affected ULTRA standalone/MB2000 worker. A periodic full reconciliation remains the recovery mechanism, not the normal revocation path.

An authoritative revocation is either:

- an `ACTIVE_MEMBERSHIP` `ENTITY_DELETE` item in a resolved fast-patch bundle; or
- an active-membership ID proven absent by a successful backend roster response through `validMemberIds` or a full-roster shadow diff.

A missing member in an arbitrary local cache lookup is not, by itself, authoritative.

## Scope

This change is limited to the MonClub Access Python application. It uses the backend's existing fast-patch and roster contracts. It does not change Dashboard behavior, backend eligibility rules, manual-sync behavior, device PIN allocation, or non-ULTRA device engines.

The change applies to ULTRA workers. PullSDK ULTRA workers keep their existing targeted delete behavior. Standalone/MB2000 ULTRA workers gain an explicit targeted revocation command.

## Architecture

The application will preserve revocation intent separately from ordinary member changes:

```text
Fast patch ENTITY_DELETE -----------+
                                     |
Roster validMemberIds/full diff -----+--> revoked_ids
                                             |
                                             v
                                  MainApp ULTRA dispatch
                                             |
                                             v
                                  UltraEngine/scheduler
                                             |
                                             v
                                  UltraDeviceWorker
                                             |
                         +-------------------+-------------------+
                         |                                       |
                    PullSDK worker                       Standalone worker
                    existing delete                      immediate delete
```

`changed_ids` continues to mean create or update work. `revoked_ids` means an authoritative deletion. If the same ID is present in both sets, revocation wins.

## Revocation Sources

### Fast patch

`MainApp.apply_fast_patch_bundle` will collect IDs from `ENTITY_DELETE` items whose entity type is `ACTIVE_MEMBERSHIP`. These IDs will be passed to the running ULTRA engine as `revoked_ids`. Membership upserts continue through `changed_ids`.

The local database patch remains first. Device work is dispatched only after the local transaction succeeds and runtime caches are invalidated.

### Backend roster synchronization

The member-shadow operation already identifies IDs removed from `validMemberIds` and IDs removed by a full-roster diff. Its result will preserve those IDs as a separate revocation set instead of merging them irreversibly into `changed_ids`.

The resulting member synchronization outcome contains:

- `changed_ids`: new or modified memberships, or `None` for a full member reconcile;
- `revoked_ids`: authoritative deletions discovered during this response.

The existing H-006 empty-roster protection remains authoritative. If H-006 refuses a mass local deletion, those refused IDs must not be emitted as revocations.

## ULTRA Routing and Coalescing

`MainApp`, `UltraEngine`, and `UltraSyncScheduler` will accept an optional `revoked_ids` set alongside `changed_ids`.

Live workers receive targeted revocation commands without waiting for the periodic scheduler. Pending commands are coalesced by active-membership ID using these rules:

1. A pending revocation cannot be downgraded by a later ordinary member-sync request.
2. A revocation upgrades an already pending ordinary member-sync request.
3. Each member ID occupies at most one pending queue position.
4. A later authoritative upsert received after a completed revocation may enqueue a new ordinary sync and re-enrol the member.

Manual-sync mode continues to suppress automatic device mutations at the existing application gate.

## Standalone Worker Behavior

For an explicit revocation of active-membership ID `N`, the standalone device PIN is `str(N)`.

Before changing the device, the worker checks `device_sync_state` for `(device_id, pin)`. This is the ownership proof that MonClub previously pushed the pin.

### Owned pin

The worker performs the following sequence inline on the worker thread and existing SDK connection:

1. Call the standalone driver's `delete_users([pin])` operation.
2. If the driver confirms deletion, remove the corresponding device sync and mirror state.
3. If deletion fails or reports the pin in `failed_pins`, immediately neutralize that pin by clearing every known pushed fingerprint slot, blanking the card, blanking the name, and setting `enabled=false`.
4. If neutralization succeeds, remove the device sync and mirror state.
5. If deletion and neutralization both fail, keep device state so full reconciliation retries the revocation.

The existing full-reconciliation delete/neutralize implementation should be factored into a shared per-pin helper so targeted and full revocations cannot diverge.

### Pin without ownership proof

The worker performs no destructive device call. It emits a critical ownership-missing telemetry event containing device ID and pin, marks the pin for reconciliation where possible, and requests an immediate full reconciliation for that worker. Existing periodic reconciliation remains the final retry path.

This deliberately protects terminals shared with another access system. An unowned pin must never be deleted solely because its number matches a MonClub active-membership ID.

## Failure Handling and Observability

The targeted path will emit events that distinguish request, outcome, and fallback:

- `MEMBER_REVOKE_REQUESTED`
- `MEMBER_REVOKE_DONE`, including whether the user was deleted or neutralized
- `MEMBER_REVOKE_FAILED`
- `MEMBER_REVOKE_OWNERSHIP_MISSING`

Failures must not be reported as successful dispatch completion. Failed pins retain their per-device state and trigger or remain eligible for full-reconcile retry.

The local HTTP fast-patch response continues to mean that the local patch was accepted, not that a physical terminal completed the deletion. End-to-end Dashboard acknowledgement is outside this change's scope.

## Safety Properties

- Only authoritative backend-derived revocations enter `revoked_ids`.
- Only MonClub-owned standalone pins are mutated.
- Revocation wins over an ordinary update when commands race.
- Failed device operations retain retry state.
- An H-006-refused roster deletion cannot become a physical mass revocation.
- PullSDK behavior does not regress.
- Periodic full reconciliation remains enabled as defense in depth.
- Manual-sync mode behavior remains unchanged.

## Test Strategy

Tests will be written and observed failing before production changes.

### Fast-patch tests

- An `ACTIVE_MEMBERSHIP` `ENTITY_DELETE` produces `revoked_ids` and not an ordinary member update for that ID.
- An upsert produces `changed_ids` and no revocation.
- If an ID occurs as both changed and revoked in one bundle, revocation wins.

### Roster synchronization tests

- A delta response missing an existing shadow ID returns it in `revoked_ids`.
- A full-roster diff returns deleted IDs in `revoked_ids`.
- An H-006-refused empty valid set emits no revocations.

### Scheduler and worker tests

- Revocation is routed immediately to every matching live ULTRA worker.
- A queued ordinary sync is upgraded to revocation.
- A queued revocation cannot be downgraded by an ordinary sync.
- PullSDK workers retain their existing targeted deletion path.

### Standalone driver tests

- An owned pin is deleted immediately.
- A failed delete is neutralized immediately.
- Successful delete/neutralization clears device sync and mirror state.
- Failed delete plus failed neutralization preserves retry state.
- An unowned pin is not modified, emits critical telemetry, and requests full reconciliation.

### Regression verification

Run the focused fast-patch, member-shadow, ULTRA scheduler, standalone revocation, standalone incremental-sync, and differential PullSDK suites. Then run the repository's complete Python test suite using its documented test command.

## Acceptance Criteria

The change is accepted when an authoritative revocation received by an online automatic-sync Access instance reaches a connected, MonClub-owned ULTRA standalone pin without waiting for the periodic full-reconcile timer; the device either deletes the user or successfully neutralizes all known access credentials. Every failure or missing-ownership case remains visible and recoverable through full reconciliation.

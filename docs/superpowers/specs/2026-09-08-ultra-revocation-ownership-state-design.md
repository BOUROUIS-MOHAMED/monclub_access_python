# ULTRA Revocation Ownership State Design

## Goal

Keep every authoritative member revocation protected while it moves through the
ULTRA worker's targeted queue, full-sync attempt, and scheduler retry handoff.
An ordinary member sync must never overtake or downgrade that revocation, and a
successful removal must not leave duplicate work behind.

## State model

The worker keeps one lock-guarded full-sync phase per revoked member ID:

- `ACTIVE`: the currently executing filtered full sync owns the revocation.
- `RETRY`: the previous full attempt did not confirm completion; the ID remains
  protected without scheduling an immediate retry.
- absent: no full-sync phase owns the ID. The revocation may instead be in the
  existing targeted-member queue or a pending full-sync request, or it has been
  confirmed and finalized.

`_confirmed_member_revoke_ids` remains evidence that physical removal already
succeeded. It is not the owner of retry scheduling.

## Transitions

All transitions involving both member and full-sync state acquire
`_member_sync_lock` before `_full_sync_lock`.

1. When a full request drains, it moves its revoked IDs to `ACTIVE` and atomically
   adopts matching targeted revocations from the member queue. Unrelated member
   work remains in order.
2. A successful full sync removes the IDs from `ACTIVE` and clears their
   confirmation evidence after completion is finalized.
3. A failed or exceptional full sync moves the IDs from `ACTIVE` to `RETRY`.
   This happens after the synchronous scheduler callback, so ordinary syncs are
   rejected throughout the callback-to-redelivery window. A missing or failing
   callback still leaves recoverable `RETRY` ownership and does not wake a loop.
4. Scheduler redelivery transfers `RETRY` ownership atomically into the targeted
   queue and/or pending full request. Exact duplicates already covered by
   `ACTIVE` do not create a second full request. An overlapping request queues
   only genuinely new revoked IDs.

## Protocol behavior

Standalone full sync continues to use its ownership-checked removal and local
atomic cleanup. PullSDK full sync executes the existing targeted absent-member
deletion for adopted/unconfirmed IDs before applying the filtered roster. The
full sync succeeds only when every authoritative revocation is confirmed.

## Tests

Deterministic regressions cover:

- failed callback handoff before scheduler redelivery;
- exact duplicate and overlapping-new full requests during an active attempt;
- full-drain adoption of an equivalent targeted revoke with no leftover queue;
- PullSDK targeted deletion preceding the filtered full roster;
- success cleanup, failure retry ownership, lock-order-safe concurrency, and all
  existing standalone, scheduler, and PullSDK behavior.

# ULTRA Revocation Ownership State Design

## Goal

Keep every authoritative member revocation protected while it moves through the
ULTRA worker's targeted queue, full-sync attempt, and scheduler retry handoff.
An ordinary member sync must never overtake or downgrade that revocation, and a
successful removal must not leave duplicate work behind.

## State model

The worker keeps two lock-guarded full-sync phase maps per member ID. The
physical-revocation map owns destructive work, while the roster-exclusion map
owns the requirement to keep the ID out of stale desired-roster snapshots.
Each map uses the same phases:

- `ACTIVE`: the currently executing filtered full sync owns the physical action
  or roster exclusion.
- `RETRY`: the previous full attempt did not confirm its physical action or
  filtered roster; the ID remains protected without scheduling an immediate retry.
- absent: no full-sync phase owns the ID. The revocation may instead be in the
  existing targeted-member queue or a pending full-sync request, or it has been
  confirmed and finalized.

`_confirmed_member_revoke_ids` remains evidence that physical removal already
succeeded. It is not the owner of retry scheduling. Pending full requests carry
both `revoked_ids` (physical work) and `excluded_ids` (snapshot filtering).
Targeted revocations additionally use `_active_member_revoke_ids` while their
device I/O is executing. This set is guarded by `_member_sync_lock`.

Worker full-sync requests also carry an explicit `require_full_refresh` intent.
The engine and scheduler set it only when their authoritative `changed_ids`
payload is `None`. This intent is separate from `revoked_ids`: the latter says
which members require physical removal, while the former says a roster refresh
must still execute even when every physical revocation is already owned.
`request_full_sync()` returns an acceptance result, not a queue-newness result:
`True` means the request was newly queued, merged into pending work, or already
covered by active/retry ownership. A caller therefore never needs a second
`has_pending_full_sync()` check after the request lock is released.
`request_member_revoke()` uses the same acceptance contract for authoritative
revocations. Queued targeted work, targeted `ACTIVE`, and pending/active/retry
full ownership all return handled from the original lock-protected request.
Revocation routing uses that one result and never re-reads pending state after
the revoke may have completed. Ordinary `request_member_sync()` retains its
existing accepted-versus-already-queued behavior and separate pending check.

At the engine/scheduler boundary, a request with `changed_ids is None` and
nonempty `revoked_ids` is one compound full-sync command. Routing does not first
enqueue the same IDs through `request_member_revoke()`: the full-sync worker
already performs each physical revocation before applying its roster filtered
by those IDs. This removes the completion gap between two worker commands.
Targeted requests whose `changed_ids` is an actual set, including `set()`, keep
the immediate member-revoke path.

## Transitions

All transitions involving both member and full-sync state acquire
`_member_sync_lock` before `_full_sync_lock`.

1. Targeted drain atomically moves an ID from the member queue to targeted
   `ACTIVE` ownership before device I/O. Success clears `ACTIVE` and retains
   confirmation proof only while a real pending/active full exclusion depends
   on it. Failure atomically restores queued ownership before full handoff.
2. A newly accepted targeted revocation atomically adds its ID to any pending
   full request's `excluded_ids`. A newly requested full sync adopts queued
   targeted revocations as physical plus exclusion work, while targeted
   `ACTIVE` IDs are exclusion-only dependencies. When a full request drains, it
   moves physical `revoked_ids` and roster `excluded_ids` to their respective
   `ACTIVE` phases. It atomically adopts
   matching targeted revocations from the member queue and any retained
   physical/exclusion `RETRY` work. Unrelated member work remains in order.
3. A successful full sync removes that attempt's physical and exclusion IDs
   from `ACTIVE` and clears physical confirmation evidence after completion is
   finalized. A queued dependent request continues protecting the same ID via
   its pending `excluded_ids` until that request drains and completes.
4. A failed or exceptional full sync atomically moves its physical and exclusion
   IDs from `ACTIVE` to `RETRY` before the synchronous scheduler callback,
   without holding worker locks during that callback. Ordinary syncs are
   rejected throughout the callback-to-redelivery window, while concurrent
   redelivery can adopt `RETRY`. A missing or failing callback still leaves
   recoverable `RETRY` ownership and does not wake a loop.
5. Scheduler redelivery or a later full request transfers `RETRY` ownership
   atomically into a pending full request. Exact explicit revoke duplicates
   already covered by `ACTIVE` do not create a second full request. An overlap
   `{A, B}` while `A` is active queues physical `{B}` but exclusions `{A, B}`.
   An ordinary full refresh queued during active `A` carries exclusion `{A}`.
6. A pure revoke-only duplicate for targeted `ACTIVE` member `A` remains
   deduplicated and returns handled without creating queue state. A request with
   `require_full_refresh=True` instead queues one
   exclusion-only full request for `A`, because the independently requested
   roster refresh must not be mistaken for duplicate physical work. It later
   filters `A` from stale cache without issuing a second removal.

Bare confirmation with no queued, active, retry, or exclusion owner is stale
generation evidence. It is cleared defensively and never suppresses a later
authoritative revoke.

## Protocol behavior

Standalone full sync continues to use its ownership-checked removal and local
atomic cleanup. PullSDK full sync executes the existing targeted absent-member
deletion only for physical `revoked_ids` before applying the roster filtered by
all `excluded_ids`. The full sync succeeds only when every physical authoritative
revocation is confirmed. Exclusion-only dependencies never cause a second
destructive call.

## Tests

Deterministic regressions cover:

- failed callback handoff before scheduler redelivery;
- exact duplicate and overlapping-new full requests during an active attempt;
- full-drain adoption of an equivalent targeted revoke with no leftover queue;
- PullSDK targeted deletion preceding the filtered full roster;
- overlapping and ordinary dependent full syncs filtering active revocations
  across the same stale cache snapshot without duplicate physical deletion;
- dependent-full failure retaining exclusion ownership through eventual success;
- blocked targeted I/O retaining visible ownership and rejecting ordinary sync;
- revoke-first/full-second execution in both drain orders;
- targeted-only success followed by re-enrolment and a new revoke generation;
- engine and scheduler compound full-refresh-plus-revoke routing as one worker
  full command, proving one physical removal and a filtered stale roster;
- drain/completion immediately after a merge, proving atomic acceptance avoids
  a scheduler fallback or second physical deletion;
- targeted revoke completion immediately after a duplicate request, proving
  revoke routing also avoids a scheduler fallback or second physical deletion;
- revoke-only routing continuing through the immediate targeted command;
- success cleanup, failure retry ownership, lock-order-safe concurrency, and all
  existing standalone, scheduler, and PullSDK behavior.

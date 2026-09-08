# ULTRA Revocation Ownership State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining ULTRA revocation lifecycle races so an authoritative ID is continuously owned by a queued, active, or retry state until confirmed removal succeeds.

**Architecture:** Keep physical revocation and stale-roster exclusion as separate lock-guarded per-ID phase maps containing `ACTIVE` and `RETRY`. Pending full requests carry `revoked_ids` for destructive work and `excluded_ids` for cache filtering. Full-drain atomically transfers matching targeted queue entries and both retry kinds into `ACTIVE` under the member-then-full lock order; success removes that attempt's ownership, while every failure moves it to `RETRY`.

Targeted member revokes have their own lock-guarded ACTIVE set during device I/O.
Full requests adopt queued targeted work physically and inherit in-flight
targeted work as exclusion-only. Confirmation proof is generation-scoped and is
cleared when no pending or active full exclusion depends on it.

**Tech Stack:** Python 3.13, `threading.Lock`, `collections.deque`, pytest, `unittest.mock`

---

### Task 1: Pin all lifecycle races with failing tests

**Files:**
- Modify: `tests/test_ultra_sync_scheduler.py`
- Modify: `tests/test_standalone_revoked_pin_removal.py`

- [ ] **Step 1: Add the failed-handoff regression**

Use a real lightweight standalone worker whose failure callback is
`UltraSyncScheduler._handle_worker_full_sync_finished`. After an explicit full
sync fails the empty-roster guard, assert the scheduler contains the retry but,
before draining/redelivering it, `request_member_sync(34439)` is false, the
confirmation proof remains, and no ordinary queue entry exists.

```python
assert scheduler._pending_revoked_ids == {34439}
assert worker.request_member_sync(34439) is False
assert worker._confirmed_member_revoke_ids == {34439}
assert list(worker._pending_member_syncs) == []
```

- [ ] **Step 2: Add exact-duplicate and overlapping-new active request tests**

Start `_drain_full_sync_commands` in a thread with a blocked standalone full-sync
stub so member 41 is genuinely active. Assert an exact duplicate creates no
pending request. In a separate test, request `{41, 43}` and assert only 43 is in
the new pending request while `has_pending_full_sync(revoked_ids={41, 43})` is true.

```python
assert worker.request_full_sync(revoked_ids={41}) is False
assert worker._pending_full_sync_request is None

assert worker.request_full_sync(revoked_ids={41, 43}) is True
assert worker._pending_full_sync_request["revoked_ids"] == {43}
assert worker.has_pending_full_sync(revoked_ids={41, 43}) is True
```

- [ ] **Step 3: Add full-drain adoption and PullSDK ordering tests**

Queue unrelated ordinary member 99 and authoritative revoke 41, then drain a
full request for 41 directly. Inside the full callback assert 41 has been removed
from all member queue sets while 99 remains. For PullSDK, fake
`DeviceSyncEngine.sync_member_on_connected_sdk` and
`run_one_device_on_connected_sdk`; assert the targeted absent-member call occurs
before the filtered full roster and member 41 is never left queued.

```python
assert events == [("targeted", 41), ("full", {99})]
assert list(worker._pending_member_syncs) == [99]
assert 41 not in worker._pending_member_revoke_ids
```

- [ ] **Step 4: Add dependent full-sync execution regressions**

Execute two full syncs against the same stale snapshot. While physical revoke A
is active, queue overlap `{A, B}` and separately queue an ordinary full refresh.
Assert both dependent full rosters exclude A, physical A executes exactly once,
and the overlap physically revokes only B. Fail a dependent full once and assert
its exclusion remains protected/retryable until a later success clears it.

- [ ] **Step 5: Add targeted lifecycle regressions**

Block targeted device I/O and assert ordinary sync cannot overtake the active
revocation. Exercise revoke-first/full-second with member-first and full-first
drain calls, proving a single physical removal and a filtered stale roster.
Finally, complete a targeted-only revoke, perform an ordinary full re-enrolment,
and prove a second authoritative generation executes another physical removal.

- [ ] **Step 6: Run the new tests and verify RED**

Run:

```powershell
python -m pytest tests/test_ultra_sync_scheduler.py -k "handoff or duplicate or overlapping or overtakes or adopted" -q
python -m pytest tests/test_standalone_revoked_pin_removal.py -k "handoff" -q
```

Expected: failures showing ordinary acceptance after handoff, duplicate pending
full requests, leftover targeted revokes, and missing PullSDK targeted deletion.

### Task 2: Implement one per-ID ownership transition

**Files:**
- Modify: `app/core/ultra_engine.py`

- [ ] **Step 1: Define and initialize the phase state**

Replace `_active_full_sync_revoked_ids` with
`_full_sync_revocation_phase: Dict[int, str]`, using module constants
`_FULL_REVOKE_ACTIVE = "active"` and `_FULL_REVOKE_RETRY = "retry"`.

- [ ] **Step 2: Make request and pending checks phase-aware**

Under `_member_sync_lock` then `_full_sync_lock`, reject ordinary member sync for
IDs in pending-full, `ACTIVE`, or `RETRY`. `request_member_revoke` returns false
for `ACTIVE`, but atomically transfers `RETRY` to the targeted member queue.
`has_pending_member_revoke` treats either phase as protected.

- [ ] **Step 3: Deduplicate full requests and adopt RETRY state**

Within `request_full_sync`, subtract `ACTIVE` IDs from the requested revocation
payload. Move requested `RETRY` IDs into the pending payload in the same full-lock
critical section. Do not create a request when every requested revoked ID is
already `ACTIVE`; when new IDs remain, preserve reason/fingerprint/full-refresh
semantics and queue only those IDs. Make `has_pending_full_sync` compare against
the union of pending, active, and retry IDs.

- [ ] **Step 4: Track roster exclusions separately from physical revocations**

Add `excluded_ids` to pending requests and a second ACTIVE/RETRY phase map for
exclusion ownership. Requests inherit all active/retry exclusions. Exact
explicit duplicates remain deduped, overlap `{A, B}` queues physical `{B}` with
exclusions `{A, B}`, and an ordinary full queued during active A carries
exclusion `{A}`. A targeted revoke accepted after an ordinary full is already
pending atomically merges its ID into that request's exclusions. Member
downgrade checks include pending and phased exclusions.

- [ ] **Step 5: Atomically adopt equivalent targeted commands at full drain**

Acquire `_member_sync_lock` and then `_full_sync_lock`, pop the pending full
request, mark its revoked IDs `ACTIVE`, rebuild `_pending_member_syncs` without
matching authoritative IDs, and remove only those IDs from the member pending
sets. Preserve unrelated revokes and ordinary syncs in their original order.
Move request exclusions to their own `ACTIVE` map and adopt both physical and
exclusion `RETRY` IDs before the request is popped.

- [ ] **Step 6: Protect targeted device I/O and scope confirmation**

Add `_active_member_revoke_ids` under `_member_sync_lock`. Member drain moves
queued revokes to ACTIVE atomically, keeps ACTIVE through I/O, and on failure
restores queue ownership before requesting a full handoff. On success, clear
ACTIVE and keep confirmation only when pending/full exclusion state depends on
it. Full requests adopt queued targeted revokes as physical+exclusion and add
targeted ACTIVE IDs as exclusion-only. Ignore and clear bare stale confirmation.

- [ ] **Step 7: Centralize completion transitions**

Add one helper which, under the member-then-full lock order, removes `ACTIVE`
entries on success or changes them to `RETRY` on failure. Move failures to
`RETRY` before notification; then invoke callbacks without either worker lock so
concurrent scheduler redelivery can adopt `RETRY`. Finalize success after its
completion callback. Apply this ordering to standalone missing-cache/normal and
PullSDK missing-cache/normal/exception exits. Confirmation evidence is cleared
only on successful completion.

- [ ] **Step 8: Confirm adopted PullSDK revocations before full roster push**

Before `run_one_device_on_connected_sdk`, call
`sync_member_on_connected_sdk` for each unconfirmed active revoked ID in sorted
order. Mark successful calls confirmed. Filter every `excluded_id` from the full
cache snapshot, but never physically delete an exclusion-only dependency. Keep
the full result unsuccessful if any physical targeted deletion is unconfirmed.

- [ ] **Step 9: Run new tests and focused suites to verify GREEN**

Run:

```powershell
python -m pytest tests/test_ultra_sync_scheduler.py tests/test_standalone_incremental_sync.py tests/test_standalone_revoked_pin_removal.py -q
```

Expected: all tests pass.

### Task 3: Verify and commit

**Files:**
- Verify: `app/core/ultra_engine.py`
- Verify: `tests/test_ultra_sync_scheduler.py`
- Verify: `tests/test_standalone_revoked_pin_removal.py`

- [ ] **Step 1: Run relevant protocol and lifecycle suites**

Run the ULTRA, standalone, PullSDK, device-sync, and revocation-state test files
listed in the parent task. Expected: all pass with only known warnings.

- [ ] **Step 2: Run full non-vendored verification**

```powershell
python -m pytest tests/ -q --ignore=tests/_pydeps --ignore-glob='**/pytest_tmp_*' --ignore-glob='**/.tmp_pytest*'
python -m py_compile app/core/ultra_engine.py tests/test_ultra_sync_scheduler.py tests/test_standalone_revoked_pin_removal.py
git diff --check
```

Expected: pytest and compilation exit 0; diff check reports no whitespace errors.

- [ ] **Step 3: Commit the coherent lifecycle fix**

```powershell
git add app/core/ultra_engine.py tests/test_ultra_sync_scheduler.py tests/test_standalone_revoked_pin_removal.py
git commit -m "fix(access): close ULTRA revocation handoff races"
```

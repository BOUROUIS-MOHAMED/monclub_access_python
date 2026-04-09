# Sync Performance Optimization Design

**Date:** 2026-04-09
**Status:** Draft
**Problem:** Backend sync endpoint takes ~36s to respond for 1,403 members. Device push takes ~30min per ZKTeco device. Both need optimization.

---

## Context

The existing delta sync (spec: `2026-04-03-delta-sync-design.md`) handles section-level skipping via version tokens — if no member changed, the entire members section is skipped. This works well when nothing changed, but when anything changes, the full 1,403-member payload is still built and sent, and all 1,200+ users are re-pushed to every device.

This spec addresses **two remaining performance bottlenecks**:

1. **Backend response time:** 36 seconds even for a full member refresh (should be <2s)
2. **Device push time:** 30 minutes per device on initial or changed-data sync (should be <8 min)

## Root Cause Analysis

### Backend 36-Second Response

`GymAccessController.java:514` calls `memberImageService.resolveAccessImageUrl(am)` inside a `.map()` over 1,403 members. Each call executes a separate SQL query against `file_link`:

```sql
SELECT l FROM FileLink l 
WHERE l.entityType = 'ACTIVE_MEMBERSHIP' 
  AND l.entityId = :amId 
  AND l.role = 'ACTIVE_MEMBERSHIP_USER_IMAGE' 
  AND l.status = 'ACTIVE'
ORDER BY l.createdAt DESC
```

**1,403 individual queries at ~25ms each = ~35 seconds.** This is a classic N+1 query problem.

All other data loading is already batched:
- Memberships: 1 EntityGraph query
- Fingerprints: 1 batch `findAllByActiveMembershipIdIn()` query
- Credentials: 1 batch query
- Freezes: 1 batch query

### Device Push 30 Minutes

For each of 1,200 users pushed to a ZKTeco device:

1. Sequential per-user processing (no parallelism within a device)
2. Fingerprint template push tries **2 table names x 5 body formats = up to 10 SDK calls** per fingerprint before finding the working combination
3. `userauthorize` push tries 4 field-name patterns

**1,200 users x ~1.5s/user (with fingerprint retries) = ~30 minutes.**

---

## Phase 1: Batch Image Query (Backend Quick Win)

### Goal
Eliminate the N+1 `resolveAccessImageUrl` bottleneck. Expected: 36s -> ~1-2s.

### Changes

#### FileLinkRepository.java
Add a new batch query method:

```java
@Query("""
    SELECT l FROM FileLink l
    JOIN FETCH l.storedFile
    WHERE l.entityType = :entityType
      AND l.entityId IN :entityIds
      AND l.role = :role
      AND l.status = com.tpjava.tpjava.Models.Enumurations.MediaLinkStatus.ACTIVE
    ORDER BY l.createdAt DESC
""")
List<FileLink> findActiveByEntityIdsAndRole(
    @Param("entityType") MediaEntityType entityType,
    @Param("entityIds") Collection<Long> entityIds,
    @Param("role") MediaFileRole role
);
```

#### MemberImageService.java
Add a new batch method:

```java
public Map<Long, String> resolveAccessImageUrlsBatch(List<Long> activeMembershipIds) {
    if (activeMembershipIds.isEmpty()) return Map.of();
    
    List<FileLink> links = fileLinkRepository.findActiveByEntityIdsAndRole(
        MediaEntityType.ACTIVE_MEMBERSHIP,
        activeMembershipIds,
        MediaFileRole.ACTIVE_MEMBERSHIP_USER_IMAGE
    );
    
    // Group by entityId, take first (most recent) per entity
    Map<Long, String> result = new HashMap<>();
    for (FileLink link : links) {
        result.computeIfAbsent(link.getEntityId(), 
            id -> resolveUrlFromStoredFile(link.getStoredFile()));
    }
    return result;
}
```

#### GymAccessController.java (lines ~498-523)
Replace per-member image resolution with batch lookup:

```
BEFORE:
  // Inside .map(am -> ...):
  memberImageService.resolveAccessImageUrl(am)   // 1,403 queries

AFTER:
  // Before .map():
  Map<Long, String> imageUrls = memberImageService
      .resolveAccessImageUrlsBatch(activeMembershipIds);
  
  // Inside .map(am -> ...):
  imageUrls.getOrDefault(am.getId(), am.getUserImage())  // in-memory lookup
```

The fallback to `am.getUserImage()` preserves legacy behavior (members without FileLink entries use the old `user_image` column).

### Files Modified
- `FileLinkRepository.java` — add `findActiveByEntityIdsAndRole()`
- `MemberImageService.java` — add `resolveAccessImageUrlsBatch()`
- `GymAccessController.java` — replace per-member call with batch + map lookup

### Testing
- Verify response is identical before/after (same image URLs)
- Measure response time with 1,403 members: target <2 seconds
- Verify legacy fallback works (members without FileLink)

---

## Phase 2: Firmware Profile Caching (Device Push Quick Win)

### Goal
Eliminate redundant SDK retry loops by caching which protocol variant works for each device. Expected: 30min -> ~5-8min per device.

### Problem Detail

In `device_sync.py`, `_push_templates()` (lines 472-524) tries fingerprint push with multiple combinations:

```python
preferred_tables = ["templatev10", "template"]  # 2 options
bodies = [                                       # 5 options
    "Pin=X\tFingerID=Y\tValid=1\tSize=Z\tTemplate=T",
    "Pin=X\tFingerID=Y\tValid=1\tSize=Z\tTmp=T",
    "Pin=X\tFingerID=Y\tValid=1\tTemplate=T",
    "Pin=X\tFingerID=Y\tSize=Z\tTemplate=T",
    "Pin=X\tFingerID=Y\tTemplate=T",
]
```

Each combination is a network round-trip (~30-50ms). For 1,200 users x 5 fingerprints x up to 10 attempts = ~60,000 SDK calls.

Similarly, `_push_authorize()` tries 4 field-name patterns for `userauthorize`.

### Changes

#### device_sync.py — Add FirmwareProfile cache

Add a per-device cache that stores which combination worked:

```python
@dataclass
class FirmwareProfile:
    template_table: str | None = None       # e.g., "templatev10"
    template_body_index: int | None = None  # e.g., 0
    authorize_body_index: int | None = None # e.g., 2
```

Storage: `dict[str, FirmwareProfile]` keyed by device IP, stored in memory (lost on restart — acceptable, re-detected in ~10 seconds on first user).

#### _push_templates() modification

```
IF firmware_profile.template_table is not None:
    # Use cached combo directly (1 SDK call)
    try_set(cached_table, cached_body)
    IF success: return
    ELSE: clear cache, fall through to retry loop

# Retry loop (same as now, but on success, cache the working combo)
for table in preferred_tables:
    for i, body_fn in enumerate(bodies):
        if try_set(table, body_fn()):
            firmware_profile.template_table = table
            firmware_profile.template_body_index = i
            return
```

#### _push_authorize() modification

Same pattern: check cache first, fall back to retry loop, cache on success.

### Impact Calculation

- First user: up to 10 attempts for templates + 4 for authorize = ~14 SDK calls (same as now)
- Remaining 1,199 users: 1 attempt for templates + 1 for authorize = ~2 SDK calls each
- **Total: ~2,412 SDK calls vs ~60,000+ currently**
- At ~40ms per call: ~97 seconds vs ~40 minutes

### Files Modified
- `device_sync.py` — add `FirmwareProfile` dataclass, modify `_push_templates()` and `_push_authorize()` to use cache

### Testing
- Verify first user still works (retry loop)
- Verify second+ users use cached profile (single attempt)
- Verify cache invalidation on failure (e.g., device firmware upgrade)
- Test with multiple devices (each gets its own profile)

---

## Phase 3: Member-Level Delta Sync (Backend Long-term)

### Goal
When the members section needs refresh, return only changed members instead of all 1,403. Expected: typical delta returns 0-10 members (~5KB) instead of 1,403 (~600KB).

### Prerequisite
Phase 1 must be completed first (batch image query).

### API Changes

Add new optional parameter to sync endpoint:

```
GET /api/v1/manager/gym/access/v1/users/get_gym_users
  ?membersVersion=...
  &membersUpdatedAfter=2026-04-09T10:30:00    // NEW
  &devicesVersion=...
  &credentialsVersion=...
  &settingsVersion=...
```

### Response Changes

Add new fields to `ActiveMemberResponse`:

```json
{
  "refreshMembers": true,
  "membersDeltaMode": true,           // NEW: true = partial update, false = full replace
  "validMemberIds": [1, 2, 3, ...],   // NEW: lightweight ID list for delete detection
  "users": [ ... ],                    // Only changed members (when deltaMode=true)
  
  // Existing fields unchanged
  "currentMembersVersion": "...",
  "refreshDevices": false,
  ...
}
```

### Backend Logic

```
IF membersVersion matches AND membersUpdatedAfter is provided:
    // True delta: only changed members
    changedMembers = query WHERE updated_at > membersUpdatedAfter
                          OR user.updated_at > membersUpdatedAfter
    validMemberIds = query all valid membership IDs (lightweight: just IDs)
    
    response.membersDeltaMode = true
    response.validMemberIds = validMemberIds
    response.users = changedMembers (with images, fingerprints)
    
ELSE IF membersVersion does NOT match:
    // Full refresh (same as today)
    response.membersDeltaMode = false
    response.validMemberIds = null
    response.users = ALL members

ELSE:
    // Nothing changed
    response.refreshMembers = false
    response.users = []
```

### Client Logic (db.py)

```python
def save_sync_cache_delta(data, refresh):
    if refresh["members"]:
        if data.get("membersDeltaMode"):
            # Partial update
            upsert_users(data["users"])           # Insert or replace changed users
            server_ids = set(data["validMemberIds"])
            local_ids = set(get_all_cached_user_ids())
            removed_ids = local_ids - server_ids
            delete_users_by_ids(removed_ids)      # Remove expired/deleted members
        else:
            # Full replace (same as today, H-006 guard applies)
            replace_cached_users(data["users"])
```

### Delete Detection Strategy

**Option 2 (chosen): ID comparison.**

Backend returns `validMemberIds` — a flat list of all currently valid active membership IDs. Client compares with local cache to find removals.

Payload cost: ~14KB for 1,403 IDs (just integers). Negligible compared to member data.

Benefits:
- No need for backend to track deletion events
- Handles all removal cases: expiration, deletion, status change, membership transfer
- Self-healing: if client cache is corrupted, IDs reconcile on next sync

### Edge Cases

1. **User info changes without ActiveMembership update:**
   - User changes name/phone/email -> `UserModel.updated_at` changes but `ActiveMembership.updated_at` may not
   - Solution: query also checks `user.updated_at > membersUpdatedAfter`

2. **Fingerprint changes:**
   - Fingerprint added/removed -> query also checks MAX fingerprint `updated_at` per membership
   - Or: include fingerprint timestamp in the membersVersion token (already done)

3. **Force full refresh:**
   - `forceFullRefreshAt` already exists -> forces `membersDeltaMode = false`
   - Client sends no `membersUpdatedAfter` on first sync -> full refresh

4. **Clock skew:**
   - `membersUpdatedAfter` is the `currentMembersVersion` timestamp from last response
   - Both generated by same server clock -> no skew possible
   - If server time changes (NTP correction), worst case is one unnecessary full refresh

### Files Modified

**Backend:**
- `GymAccessController.java` — add `membersUpdatedAfter` param, delta query logic
- `ActiveMemberResponse.java` — add `membersDeltaMode`, `validMemberIds` fields
- `ActiveMembershipRepository.java` — add `findUpdatedAfter()` query

**Python Client:**
- `db.py` — add `upsert_users()`, `delete_users_by_ids()`, `get_all_cached_user_ids()` functions
- `db.py` — modify `save_sync_cache_delta()` to handle `membersDeltaMode`
- `monclub_api.py` — send `membersUpdatedAfter` param
- `app.py` — save `membersUpdatedAfter` timestamp from response for next sync

---

## Phase 4: Differential Device Push (Device Push Long-term)

### Goal
Only push changed/removed users to devices instead of re-evaluating all 1,200. Expected: typical delta push takes ~3 seconds instead of 5+ minutes.

### Prerequisite
Phase 2 (firmware cache) and Phase 3 (member-level delta) must be completed first.

### Changes

#### app.py — Pass delta info to device sync

```python
# After save_sync_cache_delta:
if data.get("membersDeltaMode"):
    changed_ids = {u["activeMembershipId"] for u in data["users"]}
    removed_ids = local_ids - server_ids  # from Phase 3
else:
    changed_ids = None  # full sync mode
    removed_ids = set()

# Pass to device sync
device_sync.sync_all_devices(
    users=all_cached_users,
    changed_ids=changed_ids,    # None = full sync, Set = delta
    removed_ids=removed_ids,
)
```

#### device_sync.py — Accept delta hints

```python
def _sync_one_device(self, device, users, changed_ids, removed_ids, ...):
    if changed_ids is not None:
        # Delta mode: only process changed + removed users
        pins_to_sync = {user_to_pin(u) for u in users if u.id in changed_ids}
        pins_to_delete = {user_to_pin(u) for u in removed_users}
    else:
        # Full mode: use existing hash-based detection
        # (existing logic unchanged)
        ...
```

### Safety Net

The existing hash-based detection (`_compute_desired_hash`) is kept as a fallback:

- If `changed_ids` is None (full sync, first run, or force refresh) -> use hash detection
- If delta hints say "no changes" but hash detection finds mismatches -> push anyway (self-healing)
- If device was factory-reset -> access app can detect this (device returns 0 users) and trigger full push

### Force Full Push Triggers

1. Device returns 0 users when local cache has >10 -> assume factory reset, full push
2. Admin triggers force refresh from dashboard -> clears version tokens, full sync + full push
3. App restart -> first device sync always uses hash detection (no delta hints yet)

### Files Modified
- `app.py` — compute `changed_ids`/`removed_ids` from delta, pass to device sync
- `device_sync.py` — accept delta hints, skip unchanged users when hints available

---

## Implementation Order & Expected Results

| Phase | What | Effort | Backend Response | Device Push |
|-------|------|--------|------------------|-------------|
| Phase 1 | Batch image query | 2-4 hours | **36s -> ~2s** | unchanged |
| Phase 2 | Firmware profile cache | 4-6 hours | unchanged | **30min -> ~5-8min** |
| Phase 3 | Member-level delta sync | 1-2 days | **2s -> ~0.1s** (typical) | unchanged |
| Phase 4 | Differential device push | 1-2 days | unchanged | **5min -> ~3s** (typical) |

**Phase 1 + 2 are independent and can be implemented in parallel.**
Phase 3 depends on Phase 1 (batch image query must exist for delta members to also be fast).
Phase 4 depends on Phase 2 + 3.

## Sources

- [Google Calendar Incremental Sync Pattern](https://developers.google.com/workspace/calendar/api/guides/sync)
- [AWS AppSync Delta Sync Operations](https://docs.aws.amazon.com/appsync/latest/devguide/tutorial-delta-sync.html)
- [Salesforce Data 360 Integration Patterns](https://architect.salesforce.com/docs/architect/fundamentals/guide/data360_integration_patterns_and_practices)

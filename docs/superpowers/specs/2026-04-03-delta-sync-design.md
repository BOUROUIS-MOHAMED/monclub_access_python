# Delta Sync for get_gym_users Endpoint

**Date:** 2026-04-03
**Status:** Draft (v2 — post-review fixes)
**Problem:** Every 60s sync fetches ALL 1200+ members, fingerprints, devices, credentials, and settings. Response is so large (~20s+ to serialize) that clients time out, producing Broken pipe errors on the backend.

---

## Overview

Add version-token-based delta sync to the existing `GET /api/v1/manager/gym/access/v1/users/get_gym_users` endpoint. The client sends version tokens from its last successful sync; the backend compares them and only returns sections that changed. Same endpoint, backward compatible.

This follows the proven pattern already used by `AccessContentSyncService` for events/products/deals.

## Version Sections

4 independent sections, each with a version token in `"count:maxUpdatedAt"` format:

| Section | Token Param | Covers | Computed From |
|---|---|---|---|
| members | `membersVersion` | Active memberships + user info + fingerprints | `COUNT(scoped_am) + ":" + MAX(scoped_am.updatedAt) + ":" + fpCount + ":" + maxFpUpdatedAt` |
| devices | `devicesVersion` | Devices + door presets | `COUNT(device) + ":" + MAX(device.updatedAt)` for gym |
| credentials | `credentialsVersion` | Gym access credentials | `COUNT(cred) + ":" + MAX(cred.updatedAt)` for gym |
| settings | `settingsVersion` | Software settings + contract + infra + membership types | `settings.updatedAt + ":" + contractStatus + ":" + contractEndDate + ":" + infraCount + ":" + membershipTypeCount` |

**Design decision:** Fingerprints are merged into the `members` section (not a separate section). A fingerprint change triggers a full members refresh. This avoids complex partial-merge logic on the client side. Fingerprint-only changes are rare enough that this trade-off is acceptable.

**Token format:** Plain string, opaque to the client (client stores and returns as-is).

**Note:** The `lastCheckTimeStamp` parameter is vestigial (sent by the client but ignored by the backend). It is kept for backward compatibility but plays no role in delta sync.

## API Contract

### Request (query params, all optional)

```
GET /api/v1/manager/gym/access/v1/users/get_gym_users
  ?membersVersion=1200:2026-04-03T02:30:00:85:2026-04-02T10:15:00
  &devicesVersion=3:2026-04-01T08:00:00
  &credentialsVersion=50:2026-04-03T01:00:00
  &settingsVersion=2026-04-01T08:00:00:true:2026-12-31:4:5
```

When a param is absent or empty, the backend treats that section as needing full refresh (backward compatible with old clients that send no version params).

### Response

```json
{
  "contractStatus": true,
  "contractEndDate": "2026-12-31",
  "accessSoftwareSettings": { "..." },
  "membership": [ { "id": 1, "title": "Gold", "..." } ],

  "refreshMembers": true,
  "refreshDevices": false,
  "refreshCredentials": false,
  "refreshSettings": false,

  "currentMembersVersion": "1201:2026-04-03T03:10:00:85:2026-04-02T10:15:00",
  "currentDevicesVersion": "3:2026-04-01T08:00:00",
  "currentCredentialsVersion": "51:2026-04-03T03:10:00",
  "currentSettingsVersion": "2026-04-01T08:00:00:true:2026-12-31:4:5",

  "users": [],
  "devices": [],
  "infrastructures": [],
  "gymAccessCredentials": []
}
```

**Rules:**
- `contractStatus`, `contractEndDate`, `accessSoftwareSettings`, `membership` (membership types list) are ALWAYS returned (tiny payloads, always fresh).
- `refresh*` booleans indicate whether each section changed since the client's last known version.
- `current*Version` tokens are what the client MUST send on its next request.
- When `refreshX = false`, the corresponding list is empty `[]` (not null).
- When `refreshX = true`, the list contains the full current data for that section.

## Backend Logic

### Pre-processing Step (writes before reads)

The current endpoint has write-on-read side effects that must run BEFORE version computation:

```
0. PRE-PROCESSING (writes):
   a. ensureAccessSettingsExists(effectiveGym)  // may INSERT settings row
   b. Load scoped memberships:
      scopedMembers = collectMembershipScope() + filterValidForAccess()
   c. Build credentials list (with ensureCredentialExists calls)  // may INSERT credential rows
   d. flush/sync to DB so all writes are visible to version queries
```

**Important:** The `@Transactional(readOnly = true)` annotation must be changed to `@Transactional` (read-write) since this endpoint performs writes via `ensureCredentialExists` and `ensureAccessSettingsExists`.

### Version Computation (after all writes)

```
computeMembersVersion(scoped, activeMembershipIds):
  memberCount = scoped.size()
  maxMemberUpdated = scoped.stream().map(updatedAt).max()
  // Fingerprints scoped by activeMembershipIds (handles gym family correctly)
  SELECT COUNT(*), MAX(updated_at) FROM user_fingerprint
    WHERE active_membership_id IN (:activeMembershipIds)
  return memberCount + ":" + maxMemberUpdated + ":" + fpCount + ":" + maxFpUpdated

computeDevicesVersion(gymId):
  SELECT COUNT(*), MAX(updated_at) FROM gym_device
    WHERE zone.gym_agent.gym_id = :gymId
  return count + ":" + maxUpdated

computeCredentialsVersion(credentials):
  // Use the already-built credentials list (post-ensureCredentialExists)
  count = credentials.size()
  maxUpdated = credentials.stream().map(updatedAt).max()
  return count + ":" + maxUpdated

computeSettingsVersion(settings, gym, infraCount, membershipTypeCount):
  return settings.updatedAt + ":" + gym.contractIsActivated + ":"
       + gym.contractActivatedUntil + ":" + infraCount + ":" + membershipTypeCount
```

**Gym family scoping:** The `membersVersion` uses `activeMembershipIds` derived from `collectMembershipScope()`, which already includes members from family gyms. This ensures fingerprint changes in family gyms are detected.

**Credentials version:** Computed from the already-built credentials list (after `ensureCredentialExists` writes), so the version token accurately reflects the current state.

### Endpoint Flow (modified getGymAccessUsers)

```
1. Parse 4 optional version token params from request

2. PRE-PROCESSING (all writes happen here):
   a. settings = ensureAccessSettingsExists(effectiveGym)
   b. scopedMembers = collectMembershipScope() + filterValidForAccess()
   c. activeMembershipIds = scopedMembers.map(id)
   d. credentials = buildCredentialsList(scopedMembers)  // includes ensureCredentialExists
   e. membership types list (always needed, always returned)

3. Compute all 4 current version tokens (cheap: COUNT + MAX queries on committed data)

4. Determine what needs refresh:
   refreshMembers     = (clientMembersVersion == null || != currentMembersVersion)
   refreshDevices     = (clientDevicesVersion == null || != currentDevicesVersion)
   refreshCredentials = (clientCredsVersion == null || != currentCredsVersion)
   refreshSettings    = (clientSettingsVersion == null || != currentSettingsVersion)

5. Build response:
   - ALWAYS: contractStatus, contractEndDate, accessSoftwareSettings, membership types
   - ALWAYS: all refresh* booleans + current*Version tokens
   - IF refreshMembers:     populate users list (with fingerprints nested inside)
   - IF refreshDevices:     populate devices list
   - IF refreshCredentials: populate gymAccessCredentials list
   - IF refreshSettings:    populate infrastructures list
   - ELSE: set corresponding list to empty []

6. Log version comparison outcomes:
   LOG.info("[DeltaSync] gym={} members={} devices={} creds={} settings={}",
            gymId, refreshMembers, refreshDevices, refreshCredentials, refreshSettings)

7. Return response
```

### Server-Side Force Refresh

Add a `forceFullRefreshAt` field to `GymAccessSoftwareSettings`:

```java
@Column
private LocalDateTime forceFullRefreshAt;
```

When set (via admin panel or manual DB update), the backend checks:
```
if (settings.forceFullRefreshAt != null) {
    // Force all sections to refresh regardless of version tokens
    refreshMembers = refreshDevices = refreshCredentials = refreshSettings = true;
    // Include forceFullRefreshAt in settings version so it auto-clears
    // once the client syncs with the new version
}
```

Use cases: database migrations, bulk imports, manual data fixes that don't touch `updated_at`.

## Python Client Changes

### monclub_api.py

`get_sync_data()` accepts optional `version_tokens: dict` parameter:

```python
def get_sync_data(self, *, token: str, version_tokens: dict | None = None, timeout: int = 20):
    params = {"lastCheckTimeStamp": _now_epoch_ms()}
    if version_tokens:
        params.update(version_tokens)  # adds membersVersion, devicesVersion, etc.
    ...
```

### db.py

New table `sync_version_tokens`:
```sql
CREATE TABLE IF NOT EXISTS sync_version_tokens (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
```

Functions:
- `save_version_tokens(tokens: dict)` - upsert all 4 tokens
- `load_version_tokens() -> dict` - returns saved tokens or empty dict
- `clear_version_tokens()` - called on logout or cache clear

### save_sync_cache — H-006 Guard Fix

The existing `save_sync_cache` has a safety guard (H-006): if the backend returns 0 users but the local cache has >10 users, it refuses to clear the cache. With delta sync, `refreshMembers=false` sends `users: []`, which would trigger this guard.

**Fix:** Create `save_sync_cache_delta(data, refresh_flags)` that:
- Only replaces sections where `refreshX = true`
- Skips sections where `refreshX = false` (leaves cached data untouched)
- Does NOT pass empty lists to the H-006 guard
- The H-006 guard only applies when `refreshMembers = true` AND the incoming list is empty

```python
def save_sync_cache_delta(data: dict, refresh: dict):
    """
    refresh = {
        "members": True/False,
        "devices": True/False,
        "credentials": True/False,
        "settings": True/False,
    }
    """
    # Always update (tiny, always fresh):
    update_contract_status(data)
    update_access_software_settings(data)
    update_membership_types(data)

    # Conditional updates:
    if refresh["members"]:
        replace_cached_users(data["users"])  # H-006 guard applies here
    # else: leave cached users untouched

    if refresh["devices"]:
        replace_cached_devices(data["devices"])

    if refresh["credentials"]:
        replace_cached_credentials(data["gymAccessCredentials"])

    if refresh["settings"]:
        replace_cached_infrastructures(data["infrastructures"])
```

### app.py (_sync_tick)

```
1. Load version_tokens from DB
2. Call api.get_sync_data(token=auth.token, version_tokens=version_tokens)
3. Extract refresh flags from response:
   refresh = {
     "members":     data.get("refreshMembers", True),
     "devices":     data.get("refreshDevices", True),
     "credentials": data.get("refreshCredentials", True),
     "settings":    data.get("refreshSettings", True),
   }
   Note: defaults to True if field missing (old backend = full refresh)
4. Call save_sync_cache_delta(data, refresh)
5. ONLY IF cache save succeeded: save new current*Version tokens
6. If cache save failed: don't update tokens -> next sync retries
```

## Safety & Backward Compatibility

### Force Full Refresh Triggers (client-side)
- Client sends no version tokens (old client, first sync, cache cleared) -> full refresh
- Any version token is null/empty -> that section gets full refresh
- Version token format invalid/unparseable -> full refresh for that section
- Any exception during version computation -> full refresh for all

### Force Full Refresh Triggers (server-side)
- `forceFullRefreshAt` set in GymAccessSoftwareSettings -> all sections refresh
- Useful after DB migrations, bulk imports, manual data fixes

### Rollback Strategy
Version tokens are saved AFTER successful cache write. If the cache write fails:
- Old version tokens remain
- Next sync re-fetches the data that failed to cache
- Worst case: unnecessary full refresh (safe), never a missed update

### Race Condition Window
Version tokens are computed at step 3, data is loaded at step 5. If a write happens between steps 3 and 5, the loaded data may include the new record but the version token won't reflect it. On the next sync, the client sends the old token, sees a mismatch, and does a full refresh for that section. This is safe (no data loss), just one unnecessary full refresh. Accepted trade-off.

### Cache Clear Events
These clear saved version tokens, forcing full refresh:
- User logs out
- User logs in (fresh start)
- App explicitly clears cache
- Database migration/reset

### Backward Compatibility
- Old Python clients (without version params) continue to work — backend returns full data
- The endpoint signature doesn't change — new params are optional
- Response structure gains new fields (refresh*, current*Version) but existing fields remain
- Old clients ignore the new fields
- `refresh*` flags default to `true` on the client if missing from response (old backend compat)

## Performance Impact

**Best case (nothing changed):** Backend runs 4 COUNT+MAX queries (milliseconds each), returns ~500 bytes of version tokens + tiny always-included fields. No member/device/fingerprint data loaded or serialized.

**Typical case (member added):** Only members section refreshed. Devices, credentials, settings skip loading. Response size reduced by ~60-80%.

**Worst case (everything changed):** Same as today's full sync. No regression.

## Observability

Log version comparison outcomes on every sync:
```
[DeltaSync] gym=42 members=SKIP(v=1200:...) devices=SKIP credentials=REFRESH(old=49:... new=50:...) settings=SKIP
```

This allows production debugging of:
- Which sections are refreshing too often (version instability)
- Whether delta sync is actually reducing load
- Individual gym sync behavior

## Files to Modify

### Backend (monclub_backend)
- `GymAccessController.java` — Restructure endpoint: pre-processing writes first, then version computation, then conditional loading. Remove `readOnly = true`. Add version computation methods. Add logging.
- `ActiveMemberResponse.java` — Add `refreshMembers`, `refreshDevices`, `refreshCredentials`, `refreshSettings` booleans. Add `currentMembersVersion`, `currentDevicesVersion`, `currentCredentialsVersion`, `currentSettingsVersion` strings.
- `GymAccessSoftwareSettings.java` — Add `forceFullRefreshAt` field.
- `UserFingerprintRepository.java` — Add `countAndMaxUpdatedAtByActiveMembershipIdIn(List<Long> ids)` query.
- `GymDeviceRepository.java` — Add `countAndMaxUpdatedAtByZoneGymAgentGymId(Long gymId)` query.

### Python Client (monclub_access_python)
- `monclub_api.py` — Send version tokens as query params.
- `db.py` — New `sync_version_tokens` table + save/load/clear functions. New `save_sync_cache_delta()` function that respects refresh flags and bypasses H-006 guard for skipped sections.
- `app.py` — Extract refresh flags from response. Call `save_sync_cache_delta` instead of `save_sync_cache`. Save version tokens only after successful cache write.

### Dashboard (monclub_dashboard)
- No changes needed (dashboard doesn't use this endpoint).

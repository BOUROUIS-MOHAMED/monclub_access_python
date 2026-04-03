# Delta Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add version-token-based delta sync to `getGymAccessUsers` so the backend only returns changed sections, eliminating 20s timeouts on 1200-member gyms.

**Architecture:** Four independent sections (members, devices, credentials, settings) each have a `count:maxUpdatedAt` token. Client sends last-known tokens; backend compares and returns only changed sections plus always-fresh tiny fields. Pre-processing writes run before version computation to ensure token accuracy.

**Tech Stack:** Spring Boot / JPA (backend), Python / SQLite (client), existing `@Transactional` + Spring Data JPA pattern.

---

## File Map

### Backend (Java — `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava`)

| File | Change |
|---|---|
| `Models/DTO/ActiveMemberResponse.java` | Add 4 `refresh*` booleans + 4 `current*Version` strings |
| `Models/GymAccessSoftwareSettings.java` | Add `forceFullRefreshAt LocalDateTime` field |
| `Repositories/UserFingerprintRepository.java` | Add `countByActiveMembershipIdIn` + `findMaxUpdatedAtByActiveMembershipIdIn` |
| `Repositories/GymDeviceRepository.java` | Add `countByZoneGymAgentGymId` + `findMaxUpdatedAtByZoneGymAgentGymId` |
| `Controllers/GymAccessController.java` | Restructure endpoint: change `readOnly`, add 4 params, version computation, conditional loading |

### Python Client (`C:\Users\mohaa\Desktop\monclub_access_python`)

| File | Change |
|---|---|
| `app/core/db.py` | Add `sync_version_tokens` table, `save/load/clear_version_tokens`, `save_sync_cache_delta` |
| `app/api/monclub_api.py` | Add `version_tokens: dict | None` param to `get_sync_data` |
| `app/ui/app.py` | Update `_sync_tick` for delta sync; add `clear_version_tokens` on logout/login |

---

## Task 1: Backend — Add refresh flags + version strings to ActiveMemberResponse

**Files:**
- Modify: `Models/DTO/ActiveMemberResponse.java`

- [ ] **Step 1: Add the 8 new fields**

Replace the current class body in `ActiveMemberResponse.java`:

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ActiveMemberResponse {
    private boolean contractStatus;
    private String contractEndDate;
    private GymAccessSoftwareSettingsDto accessSoftwareSettings;
    private List<ActiveMemberUserDto> users;
    private List<ActiveMemberMembershipDto> membership;
    private List<GymDeviceDto> devices;
    private List<GymInfrastructureDto> infrastructures;
    private List<GymAccessCredentialDto> gymAccessCredentials;

    // Delta sync: refresh flags (true = section changed, full data returned)
    private boolean refreshMembers;
    private boolean refreshDevices;
    private boolean refreshCredentials;
    private boolean refreshSettings;

    // Delta sync: tokens the client must send on the next request
    private String currentMembersVersion;
    private String currentDevicesVersion;
    private String currentCredentialsVersion;
    private String currentSettingsVersion;
}
```

- [ ] **Step 2: Verify the file compiles**

Run from `D:\projects\MonClub\monclub_backend`:
```bash
./mvnw compile -q
```
Expected: `BUILD SUCCESS` (Lombok warnings are pre-existing and OK to ignore).

- [ ] **Step 3: Commit**

```bash
git -C "D:\projects\MonClub\monclub_backend" add src/main/java/com/tpjava/tpjava/Models/DTO/ActiveMemberResponse.java
git -C "D:\projects\MonClub\monclub_backend" commit -m "feat(delta-sync): add refresh flags and version tokens to ActiveMemberResponse"
```

---

## Task 2: Backend — Add forceFullRefreshAt to GymAccessSoftwareSettings

**Files:**
- Modify: `Models/GymAccessSoftwareSettings.java`

- [ ] **Step 1: Add the field after `optionalDataSyncDelayMinutes`**

```java
    /**
     * When set, all delta-sync sections are forced to refresh on the next client sync.
     * Cleared by the backend after triggering the forced refresh.
     */
    @Column
    private LocalDateTime forceFullRefreshAt;
```

Insert this block between `optionalDataSyncDelayMinutes` and `@CreatedDate private LocalDateTime createdAt;`.

> **JPA schema note:** If the project uses `spring.jpa.hibernate.ddl-auto=update`, Hibernate will auto-add the `force_full_refresh_at` column on startup. If the project uses Flyway or Liquibase, add a migration: `ALTER TABLE gym_access_software_settings ADD COLUMN force_full_refresh_at TIMESTAMP NULL;`

- [ ] **Step 2: Verify compile**

```bash
./mvnw compile -q
```
Expected: `BUILD SUCCESS`.

- [ ] **Step 3: Commit**

```bash
git -C "D:\projects\MonClub\monclub_backend" add src/main/java/com/tpjava/tpjava/Models/GymAccessSoftwareSettings.java
git -C "D:\projects\MonClub\monclub_backend" commit -m "feat(delta-sync): add forceFullRefreshAt field to GymAccessSoftwareSettings"
```

---

## Task 3: Backend — Add version queries to repositories

**Files:**
- Modify: `Repositories/UserFingerprintRepository.java`
- Modify: `Repositories/GymDeviceRepository.java`

- [ ] **Step 1: Add fingerprint count + max queries**

Append to `UserFingerprintRepository` (before the closing `}`):

```java
    @Query("""
        SELECT COUNT(uf) FROM UserFingerprint uf
        WHERE uf.activeMembership.id IN :ids
    """)
    long countByActiveMembershipIdIn(@Param("ids") Collection<Long> ids);

    @Query("""
        SELECT MAX(uf.updatedAt) FROM UserFingerprint uf
        WHERE uf.activeMembership.id IN :ids
    """)
    Optional<LocalDateTime> findMaxUpdatedAtByActiveMembershipIdIn(@Param("ids") Collection<Long> ids);
```

Also ensure `Collection` is imported (it already is in the existing imports).

- [ ] **Step 2: Add device count + max queries**

Append to `GymDeviceRepository` (before the closing `}`):

```java
    @Query("""
        SELECT COUNT(d) FROM GymDevice d
        WHERE d.zone.gymAgent.gym.id = :gymId
    """)
    long countByZoneGymAgentGymId(@Param("gymId") Long gymId);

    @Query("""
        SELECT MAX(d.updatedAt) FROM GymDevice d
        WHERE d.zone.gymAgent.gym.id = :gymId
    """)
    Optional<LocalDateTime> findMaxUpdatedAtByZoneGymAgentGymId(@Param("gymId") Long gymId);
```

Add these imports to `GymDeviceRepository.java`:
```java
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.time.LocalDateTime;
import java.util.Optional;
```

Also check `GymDevice` has `updatedAt` field — if not, use a `@Column` field that already exists with timestamps.

> **Note:** If `GymDevice` doesn't have `updatedAt`, use `d.createdAt` for max or add `updatedAt` with `@LastModifiedDate`.

- [ ] **Step 3: Verify compile**

```bash
./mvnw compile -q
```
Expected: `BUILD SUCCESS`.

- [ ] **Step 4: Commit**

```bash
git -C "D:\projects\MonClub\monclub_backend" add \
  src/main/java/com/tpjava/tpjava/Repositories/UserFingerprintRepository.java \
  src/main/java/com/tpjava/tpjava/Repositories/GymDeviceRepository.java
git -C "D:\projects\MonClub\monclub_backend" commit -m "feat(delta-sync): add count+max version queries to fingerprint and device repositories"
```

---

## Task 4: Backend — Restructure getGymAccessUsers for delta sync

**Files:**
- Modify: `Controllers/GymAccessController.java`

This is the biggest change. The restructured endpoint:
1. Parses 4 optional version token params
2. Runs pre-processing writes (same as today, in same order)
3. Computes 4 version tokens
4. Determines which sections need refresh
5. Returns data only for sections that changed

- [ ] **Step 1: Change @Transactional annotation**

Find line 269:
```java
    @Transactional(readOnly = true) // ✅ important for lazy doorPresets
```
Change to:
```java
    @Transactional
```
Reason: `ensureCredentialExists` and `ensureAccessSettingsExists` perform DB writes.

- [ ] **Step 2: Add 4 version token request params to the method signature**

Current signature:
```java
    public ResponseEntity<ActiveMemberResponse> getGymAccessUsers(
            HttpServletRequest httpRequest,
            @RequestParam(value = "lastCheckTimeStamp", required = false) String lastCheckTimeStamp
    ) {
```

Replace with:
```java
    public ResponseEntity<ActiveMemberResponse> getGymAccessUsers(
            HttpServletRequest httpRequest,
            @RequestParam(value = "lastCheckTimeStamp", required = false) String lastCheckTimeStamp,
            @RequestParam(value = "membersVersion", required = false) String clientMembersVersion,
            @RequestParam(value = "devicesVersion", required = false) String clientDevicesVersion,
            @RequestParam(value = "credentialsVersion", required = false) String clientCredsVersion,
            @RequestParam(value = "settingsVersion", required = false) String clientSettingsVersion
    ) {
```

- [ ] **Step 3: Add forceFullRefreshAt pre-processing**

Right after the `ensureAccessSettingsExists` call, add a force-refresh check that clears the field:

```java
        // Delta sync: handle server-side force refresh (one-shot)
        if (settings.getForceFullRefreshAt() != null) {
            settings.setForceFullRefreshAt(null);
            settings = gymAccessSoftwareSettingsRepository.save(settings);
            // null out client version tokens so all sections refresh
            clientMembersVersion = null;
            clientDevicesVersion = null;
            clientCredsVersion = null;
            clientSettingsVersion = null;
        }
```

- [ ] **Step 4: Add 4 private version computation methods to the controller**

Add these methods at the bottom of the controller class (before the last `}`):

```java
    // ─── Delta Sync: Version Token Computation ───────────────────────────────

    private String computeMembersVersion(List<ActiveMembership> scoped, List<Long> activeMembershipIds) {
        int memberCount = scoped.size();
        String maxMemberUpdated = scoped.stream()
                .map(ActiveMembership::getUpdatedAt)
                .filter(Objects::nonNull)
                .max(LocalDateTime::compareTo)
                .map(LocalDateTime::toString)
                .orElse("0");

        if (activeMembershipIds == null || activeMembershipIds.isEmpty()) {
            return memberCount + ":" + maxMemberUpdated + ":0:0";
        }

        long fpCount = userFingerprintRepository.countByActiveMembershipIdIn(activeMembershipIds);
        String maxFpUpdated = userFingerprintRepository
                .findMaxUpdatedAtByActiveMembershipIdIn(activeMembershipIds)
                .map(LocalDateTime::toString)
                .orElse("0");

        return memberCount + ":" + maxMemberUpdated + ":" + fpCount + ":" + maxFpUpdated;
    }

    private String computeDevicesVersion(Long gymId) {
        long count = gymDeviceRepository.countByZoneGymAgentGymId(gymId);
        String maxUpdated = gymDeviceRepository
                .findMaxUpdatedAtByZoneGymAgentGymId(gymId)
                .map(LocalDateTime::toString)
                .orElse("0");
        return count + ":" + maxUpdated;
    }

    private String computeCredentialsVersion(List<GymAccessCredentialDto> credentials) {
        int count = credentials.size();
        String maxUpdated = credentials.stream()
                .map(GymAccessCredentialDto::getUpdatedAt)
                .filter(Objects::nonNull)
                .max(LocalDateTime::compareTo)
                .map(LocalDateTime::toString)
                .orElse("0");
        return count + ":" + maxUpdated;
    }

    private String computeSettingsVersion(GymAccessSoftwareSettings settings, GymModel gym,
                                          int infraCount, int membershipTypeCount) {
        String settingsUpdated = settings.getUpdatedAt() != null ? settings.getUpdatedAt().toString() : "0";
        String contractStatus = String.valueOf(gym.isContractIsActivated());
        String contractEnd = gym.getContractActivatedUntil() != null ? gym.getContractActivatedUntil().toString() : "null";
        return settingsUpdated + ":" + contractStatus + ":" + contractEnd + ":" + infraCount + ":" + membershipTypeCount;
    }
```

> **Note:** `GymAccessCredentialDto.getUpdatedAt()` returns `LocalDateTime` — verify this is the case in the DTO. If it returns `String`, adapt the stream accordingly.

- [ ] **Step 5: Restructure the endpoint body — compute versions and add conditional loading**

After the credentials list is built (post-`ensureCredentialExists` writes) and memberships list is built, **before** `ActiveMemberResponse result = new ActiveMemberResponse()`:

```java
        // ─── Delta Sync: Version Computation ────────────────────────────────
        // NOTE: countByGymAgentGymId is added to GymInfrastructureRepository in Step 8.
        // The code below will NOT compile until Step 8 is complete. Do Steps 5–8 before running a compile check.
        int infraCount = gymInfrastructureRepository.countByGymAgentGymId(effectiveGymId);
        int membershipTypeCount = memberships.size();

        String currentMembersVersion    = computeMembersVersion(scoped, activeMembershipIds);
        String currentDevicesVersion    = computeDevicesVersion(effectiveGymId);
        String currentCredsVersion      = computeCredentialsVersion(credentials);
        String currentSettingsVersion   = computeSettingsVersion(settings, effectiveGym, infraCount, membershipTypeCount);

        boolean refreshMembers     = clientMembersVersion == null    || !clientMembersVersion.equals(currentMembersVersion);
        boolean refreshDevices     = clientDevicesVersion == null    || !clientDevicesVersion.equals(currentDevicesVersion);
        boolean refreshCredentials = clientCredsVersion == null      || !clientCredsVersion.equals(currentCredsVersion);
        boolean refreshSettings    = clientSettingsVersion == null   || !clientSettingsVersion.equals(currentSettingsVersion);

        org.slf4j.LoggerFactory.getLogger(getClass()).info(
            "[DeltaSync] gym={} members={} devices={} creds={} settings={}",
            effectiveGymId, refreshMembers, refreshDevices, refreshCredentials, refreshSettings);
        // ─────────────────────────────────────────────────────────────────────
```

> **Note:** `gymInfrastructureRepository.countByGymAgentGymId(Long gymId)` — add this method to `GymInfrastructureRepository` if it doesn't exist (it's a Spring Data derived query, no `@Query` needed).

- [ ] **Step 6: Update the result-building block to use refresh flags**

Replace the `ActiveMemberResponse result = new ActiveMemberResponse()` block at lines 386–408 with:

```java
        ActiveMemberResponse result = new ActiveMemberResponse();

        // Always included (tiny, always fresh)
        result.setMembership(memberships);
        result.setAccessSoftwareSettings(toSettingsDto(settings));
        if (effectiveGym != null) {
            result.setContractStatus(effectiveGym.isContractIsActivated());
            if (effectiveGym.getContractActivatedUntil() != null) {
                result.setContractEndDate(effectiveGym.getContractActivatedUntil().toString());
            }
        }

        // Delta sync flags + tokens (always returned)
        result.setRefreshMembers(refreshMembers);
        result.setRefreshDevices(refreshDevices);
        result.setRefreshCredentials(refreshCredentials);
        result.setRefreshSettings(refreshSettings);
        result.setCurrentMembersVersion(currentMembersVersion);
        result.setCurrentDevicesVersion(currentDevicesVersion);
        result.setCurrentCredentialsVersion(currentCredsVersion);
        result.setCurrentSettingsVersion(currentSettingsVersion);

        // Conditional: only load + return sections that changed
        if (refreshMembers) {
            // `members` = the List<ActiveMemberUserDto> built earlier in this method
            // (the stream-mapped list from `scoped`, variable name `members` in the existing code)
            result.setUsers(members);
        } else {
            result.setUsers(List.of());
        }

        if (refreshDevices) {
            result.setDevices(
                gymDeviceRepository.findAllByZoneGymAgentGymId(effectiveGymId)
                    .stream()
                    .map(this::toDeviceDto)
                    .filter(Objects::nonNull)
                    .toList()
            );
        } else {
            result.setDevices(List.of());
        }

        if (refreshCredentials) {
            result.setGymAccessCredentials(credentials);
        } else {
            result.setGymAccessCredentials(List.of());
        }

        if (refreshSettings) {
            result.setInfrastructures(
                gymInfrastructureRepository.findAllByGymAgentGymId(effectiveGymId)
                    .stream()
                    .map(z -> new GymInfrastructureDto(z.getId(), z.getName()))
                    .toList()
            );
        } else {
            result.setInfrastructures(List.of());
        }

        return ResponseEntity.ok(result);
```

> **Key:** The existing `devices` list computation (lines 343–348) was doing eager loading for ALL syncs. With delta sync it moves inside the `if (refreshDevices)` block above — **remove the old `List<GymDeviceDto> devices = ...` block** that ran unconditionally.

- [ ] **Step 7: Remove the old unconditional devices loading block**

Delete these lines (approx 343–348 in original):
```java
        // ✅ Devices mapped with NEW model (includes all fields + doorPresets)
        List<GymDeviceDto> devices =
                gymDeviceRepository.findAllByZoneGymAgentGymId(effectiveGymId)
                        .stream()
                        .map(this::toDeviceDto)
                        .filter(Objects::nonNull)
                        .toList();
```

- [ ] **Step 8: Add countByGymAgentGymId to GymInfrastructureRepository**

Find `GymInfrastructureRepository.java` and add:
```java
    long countByGymAgentGymId(Long gymId);
```
This is a Spring Data derived query — no `@Query` annotation needed.

- [ ] **Step 9: Verify compile**

```bash
./mvnw compile -q
```
Expected: `BUILD SUCCESS`.

- [ ] **Step 10: Manual smoke test**

Start the backend and call:
```bash
curl -s -H "Authorization: Bearer <GYM_TOKEN>" \
  "https://monclubwigo.tn/api/v1/manager/gym/access/v1/users/get_gym_users" | \
  python -m json.tool | grep -E "refresh|Version|contractStatus"
```
Expected response includes `refreshMembers: true` (first call, no tokens), plus all 4 `current*Version` strings, plus `contractStatus`.

Second call with tokens:
```bash
curl -s -H "Authorization: Bearer <GYM_TOKEN>" \
  "https://monclubwigo.tn/api/v1/manager/gym/access/v1/users/get_gym_users?membersVersion=<TOKEN>&devicesVersion=<TOKEN>&credentialsVersion=<TOKEN>&settingsVersion=<TOKEN>" | \
  python -m json.tool | grep -E "refresh|users"
```
Expected: all `refresh*: false`, `users: []`, `devices: []`, etc.

- [ ] **Step 11: Commit**

```bash
git -C "D:\projects\MonClub\monclub_backend" add \
  src/main/java/com/tpjava/tpjava/Controllers/GymAccessController.java \
  src/main/java/com/tpjava/tpjava/Repositories/GymInfrastructureRepository.java
git -C "D:\projects\MonClub\monclub_backend" commit -m "feat(delta-sync): restructure getGymAccessUsers for version-token-based delta sync"
```

---

## Task 5: Python — Add sync_version_tokens table to init_db

**Files:**
- Modify: `app/core/db.py`

- [ ] **Step 1: Add the table creation inside `init_db`**

In `init_db()`, after the last `conn.execute(...)` block (before `conn.commit()` or end of the `with` block), add:

```python
        # -----------------------------
        # delta sync: version tokens
        # -----------------------------
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_version_tokens (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
```

- [ ] **Step 2: Verify the table is created**

```bash
cd "C:\Users\mohaa\Desktop\monclub_access_python"
python -c "
from app.core.db import init_db, get_conn
init_db()
with get_conn() as c:
    rows = c.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name='sync_version_tokens'\").fetchall()
    print('Table exists:', bool(rows))
"
```
Expected output: `Table exists: True`

- [ ] **Step 3: Commit**

```bash
git -C "C:\Users\mohaa\Desktop\monclub_access_python" add app/core/db.py
git -C "C:\Users\mohaa\Desktop\monclub_access_python" commit -m "feat(delta-sync): add sync_version_tokens table to SQLite schema"
```

---

## Task 6: Python — Add save/load/clear_version_tokens to db.py

**Files:**
- Modify: `app/core/db.py`

- [ ] **Step 1: Add three functions after `init_db`**

Add these functions anywhere after `init_db` (before `save_sync_cache` is fine):

```python
# -----------------------------
# Delta sync: version tokens
# -----------------------------

def save_version_tokens(tokens: dict) -> None:
    """Upsert version tokens. tokens = {membersVersion: ..., devicesVersion: ..., ...}"""
    if not tokens:
        return
    with get_conn() as conn:
        for key, value in tokens.items():
            if value is None:
                continue
            conn.execute(
                """
                INSERT INTO sync_version_tokens (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (key, str(value)),
            )
        conn.commit()


def load_version_tokens() -> dict:
    """Return all saved version tokens, or empty dict if none."""
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM sync_version_tokens").fetchall()
        return {r["key"]: r["value"] for r in rows}


def clear_version_tokens() -> None:
    """Delete all saved version tokens (call on logout/login/cache-clear)."""
    with get_conn() as conn:
        conn.execute("DELETE FROM sync_version_tokens")
        conn.commit()
```

- [ ] **Step 2: Verify the functions work**

```bash
cd "C:\Users\mohaa\Desktop\monclub_access_python"
python -c "
from app.core.db import init_db, save_version_tokens, load_version_tokens, clear_version_tokens
init_db()
save_version_tokens({'membersVersion': '100:2026-01-01', 'devicesVersion': '3:2026-01-01'})
loaded = load_version_tokens()
print('Loaded:', loaded)
assert loaded['membersVersion'] == '100:2026-01-01', 'save/load failed'
clear_version_tokens()
assert load_version_tokens() == {}, 'clear failed'
print('All assertions passed.')
"
```
Expected: `All assertions passed.`

- [ ] **Step 3: Commit**

```bash
git -C "C:\Users\mohaa\Desktop\monclub_access_python" add app/core/db.py
git -C "C:\Users\mohaa\Desktop\monclub_access_python" commit -m "feat(delta-sync): add save/load/clear_version_tokens to db"
```

---

## Task 7: Python — Add save_sync_cache_delta to db.py

**Files:**
- Modify: `app/core/db.py`

- [ ] **Step 1: Add save_sync_cache_delta after save_sync_cache**

```python
def save_sync_cache_delta(data: dict, refresh: dict) -> None:
    """
    Delta-aware cache update. Only replaces sections where refresh[section] is True.
    Sections with refresh=False are left untouched in the local cache.

    refresh = {
        "members":     True/False,
        "devices":     True/False,
        "credentials": True/False,
        "settings":    True/False,
    }

    H-006 guard only applies when refreshMembers=True AND backend returns 0 users.
    """
    if not data:
        return

    import logging as _log
    _logger = _log.getLogger(__name__)

    updated_at = now_iso()
    contract_status = bool(data.get("contractStatus", False))
    contract_end_date = (data.get("contractEndDate") or "").strip()
    access_settings = data.get("accessSoftwareSettings") or data.get("access_software_settings") or None
    memberships = data.get("membership") or data.get("memberships") or []

    with get_conn() as conn:
        cur = conn.cursor()

        # Always: update contract meta
        cur.execute(
            """
            INSERT INTO sync_meta (id, contract_status, contract_end_date, updated_at)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                contract_status=excluded.contract_status,
                contract_end_date=excluded.contract_end_date,
                updated_at=excluded.updated_at
            """,
            (1 if contract_status else 0, contract_end_date, updated_at),
        )

        # Always: update access software settings
        if isinstance(access_settings, dict):
            s = access_settings
            try:
                cur.execute(
                    """
                    INSERT INTO sync_access_software_settings (
                        id, gym_id, access_server_host, access_server_port, access_server_enabled,
                        image_cache_enabled, image_cache_timeout_sec, image_cache_max_bytes, image_cache_max_files,
                        event_queue_max, notification_queue_max, history_queue_max, popup_queue_max,
                        decision_workers, decision_ema_alpha,
                        history_retention_days, notification_rate_limit_per_minute, notification_dedupe_window_sec,
                        notification_service_enabled, history_service_enabled,
                        agent_sync_backend_refresh_min,
                        default_authorize_door_id, sdk_read_initial_bytes,
                        optional_data_sync_delay_minutes,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        gym_id=excluded.gym_id,
                        access_server_host=excluded.access_server_host,
                        access_server_port=excluded.access_server_port,
                        access_server_enabled=excluded.access_server_enabled,
                        image_cache_enabled=excluded.image_cache_enabled,
                        image_cache_timeout_sec=excluded.image_cache_timeout_sec,
                        image_cache_max_bytes=excluded.image_cache_max_bytes,
                        image_cache_max_files=excluded.image_cache_max_files,
                        event_queue_max=excluded.event_queue_max,
                        notification_queue_max=excluded.notification_queue_max,
                        history_queue_max=excluded.history_queue_max,
                        popup_queue_max=excluded.popup_queue_max,
                        decision_workers=excluded.decision_workers,
                        decision_ema_alpha=excluded.decision_ema_alpha,
                        history_retention_days=excluded.history_retention_days,
                        notification_rate_limit_per_minute=excluded.notification_rate_limit_per_minute,
                        notification_dedupe_window_sec=excluded.notification_dedupe_window_sec,
                        notification_service_enabled=excluded.notification_service_enabled,
                        history_service_enabled=excluded.history_service_enabled,
                        agent_sync_backend_refresh_min=excluded.agent_sync_backend_refresh_min,
                        default_authorize_door_id=excluded.default_authorize_door_id,
                        sdk_read_initial_bytes=excluded.sdk_read_initial_bytes,
                        optional_data_sync_delay_minutes=excluded.optional_data_sync_delay_minutes,
                        created_at=excluded.created_at,
                        updated_at=excluded.updated_at
                    """,
                    (
                        1,
                        _to_int_or_none(s.get("gymId") if "gymId" in s else s.get("gym_id")),
                        _safe_str(s.get("accessServerHost") if "accessServerHost" in s else s.get("access_server_host"), ""),
                        _to_int_or_none(s.get("accessServerPort") if "accessServerPort" in s else s.get("access_server_port")),
                        _bool_to_i(s.get("accessServerEnabled", True), default=1),
                        _bool_to_i(s.get("imageCacheEnabled", True), default=1),
                        _to_int_or_none(s.get("imageCacheTimeoutSec", 2)),
                        _to_int_or_none(s.get("imageCacheMaxBytes", 5242880)),
                        _to_int_or_none(s.get("imageCacheMaxFiles", 1000)),
                        _to_int_or_none(s.get("eventQueueMax", 5000)),
                        _to_int_or_none(s.get("notificationQueueMax", 5000)),
                        _to_int_or_none(s.get("historyQueueMax", 5000)),
                        _to_int_or_none(s.get("popupQueueMax", 5000)),
                        _to_int_or_none(s.get("decisionWorkers", 1)),
                        _to_float_or_none(s.get("decisionEmaAlpha", 0.2)),
                        _to_int_or_none(s.get("historyRetentionDays", 30)),
                        _to_int_or_none(s.get("notificationRateLimitPerMinute", 30)),
                        _to_int_or_none(s.get("notificationDedupeWindowSec", 30)),
                        _bool_to_i(s.get("notificationServiceEnabled", True), default=1),
                        _bool_to_i(s.get("historyServiceEnabled", True), default=1),
                        _to_int_or_none(s.get("agentSyncBackendRefreshMin", 30)),
                        _to_int_or_none(s.get("defaultAuthorizeDoorId", 15)),
                        _to_int_or_none(s.get("sdkReadInitialBytes", 1048576)),
                        _to_int_or_none(s.get("optionalDataSyncDelayMinutes", 60)),
                        _safe_str(s.get("createdAt"), ""),
                        _safe_str(s.get("updatedAt"), updated_at) or updated_at,
                    ),
                )
            except Exception:
                pass  # never break sync

        # Always: update membership types
        cur.execute("DELETE FROM sync_memberships")
        for m in memberships:
            if not isinstance(m, dict):
                continue
            cur.execute(
                "INSERT INTO sync_memberships (id, title, description, price, duration_in_days) VALUES (?, ?, ?, ?, ?)",
                (m.get("id"), m.get("title"), m.get("description"), m.get("price"), m.get("durationInDays")),
            )

        # Conditional: members (users + fingerprints)
        if refresh.get("members", True):
            users = data.get("users") or []
            if not users:
                old_count = cur.execute("SELECT COUNT(*) FROM sync_users").fetchone()[0]
                if old_count > 10:
                    _logger.error(
                        f"[DB] save_sync_cache_delta: backend returned 0 users (refreshMembers=True) "
                        f"but local cache has {old_count}. Refusing to clear — likely backend error."
                    )
                    conn.commit()
                    return
            cur.execute("DELETE FROM sync_users")
            for u in users:
                if not isinstance(u, dict):
                    continue
                fps = u.get("fingerprints") or []
                if not isinstance(fps, list):
                    fps = []
                am_id = u.get("activeMembershipId")
                m_id = u.get("membershipId")
                if am_id is None or str(am_id).strip() == "":
                    am_id = m_id
                cur.execute(
                    """
                    INSERT OR REPLACE INTO sync_users (
                        user_id, active_membership_id, membership_id,
                        full_name, phone, email, valid_from, valid_to,
                        first_card_id, second_card_id, image,
                        fingerprints_json, face_id, account_username_id, qr_code_payload, birthday
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        u.get("userId"), am_id, m_id,
                        u.get("fullName"), u.get("phone"), u.get("email"),
                        u.get("validFrom"), u.get("validTo"),
                        u.get("firstCardId"), u.get("secondCardId"), u.get("image"),
                        json.dumps(fps, ensure_ascii=False),
                        u.get("faceId"),
                        u.get("accountUsernameId") or u.get("account_username_id"),
                        u.get("qrCodePayload"), u.get("birthday"),
                    ),
                )

        # Conditional: devices
        if refresh.get("devices", True):
            cur.execute("DELETE FROM sync_devices")
            cur.execute("DELETE FROM sync_device_door_presets")
            devices = data.get("devices") or []
            for d in devices:
                if not isinstance(d, dict):
                    continue
                presets = d.get("doorPresets") or []
                if isinstance(presets, list):
                    for p in presets:
                        if not isinstance(p, dict):
                            continue
                        cur.execute(
                            """
                            INSERT INTO sync_device_door_presets (
                                remote_id, device_id, door_number, pulse_seconds, door_name, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                _to_int_or_none(p.get("id")),
                                _to_int_or_none(p.get("deviceId") or d.get("id")),
                                _to_int_or_none(p.get("doorNumber")),
                                _to_int_or_none(p.get("pulseSeconds")),
                                _safe_str(p.get("doorName"), ""),
                                _safe_str(p.get("createdAt"), None),
                                _safe_str(p.get("updatedAt"), None),
                            ),
                        )
                adm_raw = d.get("accessDataMode") or d.get("access_data_mode") or "DEVICE"
                adm = str(adm_raw or "").strip().upper()
                if adm not in ("DEVICE", "AGENT", "ULTRA"):
                    adm = "DEVICE"
                # INSERT the device row — copy the same INSERT from save_sync_cache
                # (reference save_sync_cache lines ~1422–1573 for the full column list)
                # This is identical to the existing device insert in save_sync_cache.
                # Copy the full INSERT OR REPLACE statement from save_sync_cache here.
                # See save_sync_cache for the complete column/value list.
                _insert_device_row(cur, d, adm)

        # Conditional: credentials
        if refresh.get("credentials", True):
            cur.execute("DELETE FROM sync_gym_access_credentials")
            creds = data.get("gymAccessCredentials") or data.get("gym_access_credentials") or []
            for c in creds:
                if not isinstance(c, dict):
                    continue
                cur.execute(
                    """
                    INSERT INTO sync_gym_access_credentials (
                        id, gym_id, account_id, secret_hex, enabled, rotated_at, created_at, updated_at,
                        granted_active_membership_ids_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        c.get("id"),
                        c.get("gymId") or c.get("gym_id"),
                        c.get("accountId") or c.get("account_id"),
                        c.get("secretHex") or c.get("secret_hex"),
                        _bool_to_i(c.get("enabled", True), default=1),
                        _safe_str(c.get("rotatedAt") or c.get("rotated_at"), None),
                        _safe_str(c.get("createdAt") or c.get("created_at"), None),
                        _safe_str(c.get("updatedAt") or c.get("updated_at"), None),
                        json.dumps(
                            c.get("grantedActiveMembershipIds") or c.get("granted_active_membership_ids") or [],
                            ensure_ascii=False,
                        ),
                    ),
                )

        # Conditional: settings (infrastructures)
        if refresh.get("settings", True):
            cur.execute("DELETE FROM sync_infrastructures")
            infras = data.get("infrastructures") or data.get("infrastructure") or []
            for z in infras:
                if not isinstance(z, dict):
                    continue
                cur.execute(
                    "INSERT INTO sync_infrastructures (id, name) VALUES (?, ?)",
                    (z.get("id"), z.get("name")),
                )

        conn.commit()
```

> **Important:** The device INSERT is identical to the one in `save_sync_cache`. To avoid duplicating a 50-line INSERT, extract it into a private helper `_insert_device_row(cur, d, adm)` — a simple refactor within `db.py`. Read the device INSERT block in `save_sync_cache` (lines ~1422–1573) and extract it.

- [ ] **Step 2: Extract _insert_device_row helper**

Create a module-private function `_insert_device_row(cur, d: dict, adm: str)` containing the device INSERT SQL from `save_sync_cache`. Then call `_insert_device_row(cur, d, adm)` from both `save_sync_cache` (replacing the inline INSERT) and `save_sync_cache_delta`.

- [ ] **Step 3: Also check sync_gym_access_credentials schema exists**

In `init_db`, verify there's a `CREATE TABLE IF NOT EXISTS sync_gym_access_credentials` block. If not, add:
```python
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_gym_access_credentials (
                id INTEGER PRIMARY KEY,
                gym_id INTEGER,
                account_id INTEGER,
                secret_hex TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                rotated_at TEXT,
                created_at TEXT,
                updated_at TEXT,
                granted_active_membership_ids_json TEXT NOT NULL DEFAULT '[]'
            );
            """
        )
```

- [ ] **Step 4: Verify save_sync_cache_delta is importable**

```bash
cd "C:\Users\mohaa\Desktop\monclub_access_python"
python -c "from app.core.db import save_sync_cache_delta; print('import OK')"
```
Expected: `import OK`

- [ ] **Step 5: Commit**

```bash
git -C "C:\Users\mohaa\Desktop\monclub_access_python" add app/core/db.py
git -C "C:\Users\mohaa\Desktop\monclub_access_python" commit -m "feat(delta-sync): add save_sync_cache_delta and _insert_device_row helper to db"
```

---

## Task 8: Python — Add version_tokens param to get_sync_data

**Files:**
- Modify: `app/api/monclub_api.py:137`

- [ ] **Step 1: Modify get_sync_data signature and params**

Current (line 137):
```python
    def get_sync_data(self, *, token: str, timeout: int = 20) -> Dict[str, Any]:
```
And (line 143):
```python
        params = {"lastCheckTimeStamp": _now_epoch_ms()}
```

Change to:
```python
    def get_sync_data(self, *, token: str, version_tokens: dict | None = None, timeout: int = 20) -> Dict[str, Any]:
```
And after `params = {"lastCheckTimeStamp": _now_epoch_ms()}`:
```python
        if version_tokens:
            params.update(version_tokens)
```

- [ ] **Step 2: Verify the change**

```bash
cd "C:\Users\mohaa\Desktop\monclub_access_python"
python -c "
from app.api.monclub_api import MonClubApi
import inspect
sig = inspect.signature(MonClubApi.get_sync_data)
print('params:', list(sig.parameters.keys()))
assert 'version_tokens' in sig.parameters, 'version_tokens param missing'
print('OK')
"
```
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git -C "C:\Users\mohaa\Desktop\monclub_access_python" add app/api/monclub_api.py
git -C "C:\Users\mohaa\Desktop\monclub_access_python" commit -m "feat(delta-sync): pass version_tokens query params in get_sync_data"
```

---

## Task 9: Python — Wire exports in access/store.py

> **Do this before Task 10** — app.py imports from `access.store` and will fail at runtime if these aren't exported yet.

**Files:**
- Modify: `access/store.py` (or wherever `save_sync_cache` is re-exported)

- [ ] **Step 1: Find where save_sync_cache is exported**

```bash
grep -r "save_sync_cache" "C:\Users\mohaa\Desktop\monclub_access_python\access\" --include="*.py" -l
```

- [ ] **Step 2: Add new exports alongside save_sync_cache**

In that file, find the line that exports/imports `save_sync_cache` and add the new functions:
```python
from app.core.db import (
    ...
    save_sync_cache,
    save_sync_cache_delta,
    save_version_tokens,
    load_version_tokens,
    clear_version_tokens,
    ...
)
```

- [ ] **Step 3: Verify**

```bash
cd "C:\Users\mohaa\Desktop\monclub_access_python"
python -c "from access.store import save_version_tokens, load_version_tokens, clear_version_tokens, save_sync_cache_delta; print('OK')"
```

- [ ] **Step 4: Commit**

```bash
git -C "C:\Users\mohaa\Desktop\monclub_access_python" add access/store.py
git -C "C:\Users\mohaa\Desktop\monclub_access_python" commit -m "feat(delta-sync): export version token and delta cache functions from access.store"
```

---

## Task 10: Python — Update _sync_tick in app.py for delta sync

**Files:**
- Modify: `app/ui/app.py`

- [ ] **Step 1: Add imports at the top of app.py**

In the `from access.store import (...)` block, add the new functions (already exported in Task 9):

```python
from access.store import (
    ...
    save_sync_cache,
    save_sync_cache_delta,
    save_version_tokens,
    load_version_tokens,
    clear_version_tokens,
    ...
)
```

- [ ] **Step 2: Update the work() function inside _sync_tick**

Current `work()` body (lines 979–988):
```python
        def work():
            sync_online = False
            try:
                api = self._api()
                data = api.get_sync_data(token=auth.token)
                save_sync_cache(data)
                self.logger.info("getSyncData OK: cache updated.")
                sync_online = True
                ...
```

Replace with:
```python
        def work():
            sync_online = False
            try:
                api = self._api()
                version_tokens = load_version_tokens()
                data = api.get_sync_data(token=auth.token, version_tokens=version_tokens or None)

                refresh = {
                    "members":     data.get("refreshMembers", True),
                    "devices":     data.get("refreshDevices", True),
                    "credentials": data.get("refreshCredentials", True),
                    "settings":    data.get("refreshSettings", True),
                }

                save_sync_cache_delta(data, refresh)

                # Save new version tokens ONLY after successful cache write
                new_tokens = {
                    k: data[k]
                    for k in ("currentMembersVersion", "currentDevicesVersion",
                              "currentCredentialsVersion", "currentSettingsVersion")
                    if data.get(k)
                }
                if new_tokens:
                    save_version_tokens(new_tokens)

                self.logger.info(
                    "getSyncData OK (delta): members=%s devices=%s creds=%s settings=%s",
                    refresh["members"], refresh["devices"], refresh["credentials"], refresh["settings"],
                )
                sync_online = True
                self._last_sync_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                self._last_sync_ok = True
                self._last_sync_error = None
```

> **Fallback note:** If `data` doesn't have `refresh*` fields (old backend), all flags default to `True` → `save_sync_cache_delta` behaves exactly like `save_sync_cache`. Backward compatible.

- [ ] **Step 3: Add clear_version_tokens to force_login and clear_auth**

In `force_login()` (line 658), after `clear_auth_token()`:
```python
        clear_version_tokens()
```

In `clear_auth()` (line 672), after `clear_auth_token()`:
```python
        clear_version_tokens()
```

- [ ] **Step 4: Commit**

```bash
git -C "C:\Users\mohaa\Desktop\monclub_access_python" add app/ui/app.py
git -C "C:\Users\mohaa\Desktop\monclub_access_python" commit -m "feat(delta-sync): update _sync_tick to use delta sync with version tokens"
```

---

## Task 11: End-to-end verification

- [ ] **Step 1: Start the Python app and observe first sync**

Watch the logs for:
```
getSyncData OK (delta): members=True devices=True creds=True settings=True
```
(First sync after tokens are cleared → full refresh.)

- [ ] **Step 2: Wait for second sync (60s) and observe**

Watch for:
```
getSyncData OK (delta): members=False devices=False creds=False settings=False
```
(No changes → no data loaded → fast response.)

- [ ] **Step 3: Verify access still works**

Scan an RFID or fingerprint. Member should be recognized (cache still populated correctly).

- [ ] **Step 4: Verify logout clears tokens**

Log out via the UI. In the DB:
```bash
python -c "
from app.core.db import load_version_tokens
print('Tokens after logout:', load_version_tokens())
"
```
Expected: `Tokens after logout: {}`

---

## Rollback

If delta sync causes issues:
1. In Python `_sync_tick`: remove `version_tokens` from `get_sync_data` call → backend returns full data
2. Keep `save_sync_cache` call instead of `save_sync_cache_delta` — old behavior restored
3. No DB migration rollback needed (table is additive, `sync_version_tokens` is harmless if empty)
4. Backend: revert `GymAccessController.java` to old endpoint (all flags default to True, full data returned)

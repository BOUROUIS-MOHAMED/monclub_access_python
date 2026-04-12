# Fast Patch Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an end-to-end fast-patch pipeline so backend-confirmed access changes reach the local Access app immediately, update hot local verification state immediately, and trigger only the necessary runtime and device actions.

**Architecture:** The backend becomes the canonical patch resolver through one generic `AccessPatchBundle` endpoint. The dashboard becomes a best-effort forwarder: after a successful mutation it resolves a canonical bundle, posts it to local Access, then still triggers `sync_now` as fallback. The Access app adds a dedicated fast-patch apply pipeline with transactional SQLite writes, revision journals, hot-cache invalidation, targeted runtime actions, and one background reconcile per bundle.

**Tech Stack:** Python 3.11+ with pytest and SQLite, Java 17 / Spring Boot 3.2 with JUnit 5, React 19 + TypeScript + Vite

**Spec:** `docs/superpowers/specs/2026-04-12-fast-patch-pipeline-design.md`

**Execution Note:** `mon_club_dashboard` and `monclub_backend` are outside the current writable workspace root. Inline implementation will require escalated write approval for those two repos.

---

## File Map

| Action | File | Responsibility |
|---|---|---|
| Create | `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\DTO\AccessPatchChangeRefDto.java` | Request DTO for generic bundle resolver |
| Create | `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\DTO\AccessPatchBundleDto.java` | Bundle envelope returned to dashboard |
| Create | `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\DTO\AccessPatchItemDto.java` | Per-item patch payload + impact hints |
| Create | `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Services\AccessPatchBundleService.java` | Canonical bundle resolution for all supported change refs |
| Modify | `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Controllers\GymAccessController.java` | New `patch-bundles/resolve` endpoint and reuse of existing access projection helpers |
| Create | `D:\projects\MonClub\monclub_backend\src\test\java\com\tpjava\tpjava\Controllers\GymAccessControllerFastPatchBundleTest.java` | Resolver-focused backend unit tests |
| Create | `C:\Users\mohaa\Desktop\monclub_access_python\app\core\fast_patch.py` | Bundle validation, key normalization, action aggregation helpers |
| Modify | `C:\Users\mohaa\Desktop\monclub_access_python\app\core\db.py` | Fast-patch journals, revision ledger, transactional per-section apply helpers |
| Modify | `C:\Users\mohaa\Desktop\monclub_access_python\app\api\local_access_api_v2.py` | New localhost `fast-patch-bundle` endpoint |
| Modify | `C:\Users\mohaa\Desktop\monclub_access_python\app\ui\app.py` | Runtime action executor, cache invalidation hooks, reconcile scheduling |
| Modify | `C:\Users\mohaa\Desktop\monclub_access_python\app\core\realtime_agent.py` | DecisionService cache reset hook |
| Modify | `C:\Users\mohaa\Desktop\monclub_access_python\app\core\ultra_engine.py` | ULTRA hot-cache reset hook and targeted sync handoff |
| Create | `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_fast_patch_db.py` | Fast-patch storage and stale-revision tests |
| Create | `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_fast_patch_api.py` | Local API fast-patch endpoint tests |
| Create | `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_fast_patch_runtime.py` | Runtime action, cache invalidation, and targeted sync tests |
| Create | `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\services\AccessPatchDispatchService.ts` | Shared resolve-and-dispatch helper for dashboard mutation flows |
| Modify | `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\services\LocalAccessService.ts` | Local bundle POST helper alongside existing `sync_now` helper |
| Modify | `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\ActiveMembership\view\active-membership-form.tsx` | Membership create/update fast-patch dispatch |
| Modify | `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\ActiveMembership\view\active-membership-fingerprints-dialog.tsx` | Fingerprint add/delete fast-patch dispatch |
| Modify | `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\GymDevices\view\gym-devices-view.tsx` | Device and door-preset fast-patch dispatch |
| Modify | `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\UserAccount\GymAccessSoftwareSettingsView.tsx` | Settings fast-patch dispatch |
| Modify | `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\GymInfrastructure\view\gym-infrastructure-view.tsx` | Infrastructure fast-patch dispatch |
| Modify | `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\Membership\view\membership-view.tsx` | Membership-type fast-patch dispatch |

**Current repo reality:** no dedicated dashboard credential mutation page was found in `mon_club_dashboard`. The dispatcher must support `CREDENTIALS` change refs, and backend + Access must support them fully, but no existing dashboard callsite is available to wire today.

---

## Task 1: Backend Bundle Contract and Resolver Skeleton

**Files:**
- Create: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\DTO\AccessPatchChangeRefDto.java`
- Create: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\DTO\AccessPatchBundleDto.java`
- Create: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\DTO\AccessPatchItemDto.java`
- Create: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Services\AccessPatchBundleService.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Controllers\GymAccessController.java`
- Test: `D:\projects\MonClub\monclub_backend\src\test\java\com\tpjava\tpjava\Controllers\GymAccessControllerFastPatchBundleTest.java`

- [ ] **Step 1: Write the failing backend tests**

Create `GymAccessControllerFastPatchBundleTest.java`:

```java
package com.tpjava.tpjava.Controllers;

import com.tpjava.tpjava.Models.DTO.AccessPatchBundleDto;
import com.tpjava.tpjava.Models.DTO.AccessPatchChangeRefDto;
import com.tpjava.tpjava.Models.DTO.AccessPatchItemDto;
import com.tpjava.tpjava.Services.AccessPatchBundleService;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GymAccessControllerFastPatchBundleTest {

    @Test
    void fingerprintChange_normalizesToActiveMembershipChangeRef() {
        AccessPatchChangeRefDto ref = AccessPatchChangeRefDto.builder()
                .entityType("FINGERPRINT")
                .entityId(321L)
                .relatedActiveMembershipId(99L)
                .operation("UPDATE")
                .build();

        AccessPatchChangeRefDto normalized = AccessPatchBundleService.normalizeChangeRef(ref);

        assertThat(normalized.getEntityType()).isEqualTo("ACTIVE_MEMBERSHIP");
        assertThat(normalized.getEntityId()).isEqualTo(99L);
    }

    @Test
    void membershipBundle_wrapsCanonicalProjectionAsEntityUpsert() {
        AccessPatchItemDto item = AccessPatchItemDto.builder()
                .kind("ENTITY_UPSERT")
                .entityType("ACTIVE_MEMBERSHIP")
                .entityId(88L)
                .revision("2026-04-12T12:00:01Z")
                .payload(java.util.Map.of("activeMembershipId", 88L))
                .build();

        AccessPatchBundleDto bundle = AccessPatchBundleDto.builder()
                .schemaVersion(1)
                .bundleId("bundle-1")
                .gymId(42L)
                .items(List.of(item))
                .requiresReconcile(true)
                .build();

        assertThat(bundle.getItems()).hasSize(1);
        assertThat(bundle.getItems().get(0).getKind()).isEqualTo("ENTITY_UPSERT");
        assertThat(bundle.isRequiresReconcile()).isTrue();
    }
}
```

- [ ] **Step 2: Run the backend test to confirm it fails**

Run:

```bash
cd D:\projects\MonClub\monclub_backend
mvn -q -Dtest=GymAccessControllerFastPatchBundleTest test
```

Expected: FAIL with missing DTO / service symbols

- [ ] **Step 3: Add DTOs and service skeleton**

Create `AccessPatchChangeRefDto.java`:

```java
package com.tpjava.tpjava.Models.DTO;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AccessPatchChangeRefDto {
    private Integer schemaVersion;
    private String entityType;
    private Long entityId;
    private Long relatedActiveMembershipId;
    private String operation;
    private String source;
    private String requestedAt;
}
```

Create `AccessPatchItemDto.java`:

```java
package com.tpjava.tpjava.Models.DTO;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class AccessPatchItemDto {
    private String itemId;
    private String kind;
    private String entityType;
    private Long entityId;
    private String revision;
    private Map<String, Object> payload;
    private Map<String, Object> impact;
}
```

Create `AccessPatchBundleDto.java`:

```java
package com.tpjava.tpjava.Models.DTO;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class AccessPatchBundleDto {
    private Integer schemaVersion;
    private String bundleId;
    private Long gymId;
    private String generatedAt;
    private List<AccessPatchItemDto> items;
    private boolean requiresReconcile;
}
```

Create `AccessPatchBundleService.java` with the initial normalization helper:

```java
package com.tpjava.tpjava.Services;

import com.tpjava.tpjava.Models.DTO.AccessPatchChangeRefDto;

public class AccessPatchBundleService {

    public static AccessPatchChangeRefDto normalizeChangeRef(AccessPatchChangeRefDto ref) {
        if (ref == null) return null;
        if (!"FINGERPRINT".equalsIgnoreCase(ref.getEntityType())) return ref;
        return AccessPatchChangeRefDto.builder()
                .schemaVersion(ref.getSchemaVersion())
                .entityType("ACTIVE_MEMBERSHIP")
                .entityId(ref.getRelatedActiveMembershipId())
                .operation(ref.getOperation())
                .source(ref.getSource())
                .requestedAt(ref.getRequestedAt())
                .build();
    }
}
```

- [ ] **Step 4: Add the resolver endpoint skeleton**

In `GymAccessController.java`, add the new endpoint:

```java
@PostMapping("/manager/gym/access/v1/patch-bundles/resolve")
public ResponseEntity<AccessPatchBundleDto> resolveFastPatchBundle(
        @RequestBody AccessPatchChangeRefDto changeRef,
        HttpServletRequest httpRequest
) {
    MainAccountModel sender = Utils.requireGymAccount(httpRequest, jwtService, mainAccountRepository);
    AccessPatchChangeRefDto normalized = AccessPatchBundleService.normalizeChangeRef(changeRef);
    AccessPatchBundleDto dto = AccessPatchBundleDto.builder()
            .schemaVersion(1)
            .bundleId(java.util.UUID.randomUUID().toString())
            .gymId(sender.getGym().getId())
            .generatedAt(java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).toString())
            .items(java.util.List.of())
            .requiresReconcile(true)
            .build();
    return ResponseEntity.ok(dto);
}
```

- [ ] **Step 5: Run the backend test to confirm it passes**

Run:

```bash
cd D:\projects\MonClub\monclub_backend
mvn -q -Dtest=GymAccessControllerFastPatchBundleTest test
```

Expected: PASS

- [ ] **Step 6: Commit the backend contract skeleton**

```bash
cd D:\projects\MonClub\monclub_backend
git add src/main/java/com/tpjava/tpjava/Models/DTO/AccessPatchChangeRefDto.java src/main/java/com/tpjava/tpjava/Models/DTO/AccessPatchBundleDto.java src/main/java/com/tpjava/tpjava/Models/DTO/AccessPatchItemDto.java src/main/java/com/tpjava/tpjava/Services/AccessPatchBundleService.java src/main/java/com/tpjava/tpjava/Controllers/GymAccessController.java src/test/java/com/tpjava/tpjava/Controllers/GymAccessControllerFastPatchBundleTest.java
git commit -m "feat(access): add fast patch bundle contract skeleton"
```

---

## Task 2: Backend Resolver Coverage for Memberships, Devices, and Section Snapshots

**Files:**
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Services\AccessPatchBundleService.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Controllers\GymAccessController.java`
- Test: `D:\projects\MonClub\monclub_backend\src\test\java\com\tpjava\tpjava\Controllers\GymAccessControllerFastPatchBundleTest.java`

- [ ] **Step 1: Extend the failing tests to cover all supported change types**

Add these tests to `GymAccessControllerFastPatchBundleTest.java`:

```java
@Test
void resolveItemKey_usesSectionKeysForSettingsCredentialsInfrastructureAndMembershipType() {
    assertThat(AccessPatchBundleService.patchKey("SETTINGS", 1L)).isEqualTo("SECTION:SETTINGS");
    assertThat(AccessPatchBundleService.patchKey("CREDENTIALS", 1L)).isEqualTo("SECTION:CREDENTIALS");
    assertThat(AccessPatchBundleService.patchKey("INFRASTRUCTURES", 1L)).isEqualTo("SECTION:INFRASTRUCTURES");
    assertThat(AccessPatchBundleService.patchKey("MEMBERSHIP_TYPE", 1L)).isEqualTo("SECTION:MEMBERSHIP_TYPE");
}

@Test
void membershipTypeChange_resolvesAsSectionReplace() {
    AccessPatchItemDto item = AccessPatchBundleService.sectionReplace(
            "MEMBERSHIP_TYPE",
            "2026-04-12T12:00:01Z",
            java.util.Map.of("membership", java.util.List.of(java.util.Map.of("id", 7L, "title", "Gold"))),
            java.util.Map.of("requiresDeviceRescope", true)
    );

    assertThat(item.getKind()).isEqualTo("SECTION_REPLACE");
    assertThat(item.getEntityType()).isEqualTo("MEMBERSHIP_TYPE");
    assertThat(item.getImpact()).containsEntry("requiresDeviceRescope", true);
}

@Test
void deviceChange_resolvesAsEntityUpsertWithDeviceImpact() {
    AccessPatchItemDto item = AccessPatchBundleService.entityUpsert(
            "GYM_DEVICE",
            55L,
            "2026-04-12T12:00:01Z",
            java.util.Map.of("id", 55L, "accessDataMode", "ULTRA"),
            java.util.Map.of("affectedDeviceIds", java.util.List.of(55L), "requiresControlledRestart", true)
    );

    assertThat(item.getKind()).isEqualTo("ENTITY_UPSERT");
    assertThat(item.getEntityType()).isEqualTo("GYM_DEVICE");
    assertThat(item.getImpact()).containsEntry("requiresControlledRestart", true);
}
```

- [ ] **Step 2: Run the backend test to confirm it fails**

Run:

```bash
cd D:\projects\MonClub\monclub_backend
mvn -q -Dtest=GymAccessControllerFastPatchBundleTest test
```

Expected: FAIL with missing helper methods

- [ ] **Step 3: Implement helper builders and resolver switch**

In `AccessPatchBundleService.java`, expand the service:

```java
public static String patchKey(String entityType, Long entityId) {
    String normalized = String.valueOf(entityType == null ? "" : entityType).trim().toUpperCase();
    if (normalized.equals("SETTINGS") || normalized.equals("CREDENTIALS")
            || normalized.equals("INFRASTRUCTURES") || normalized.equals("MEMBERSHIP_TYPE")) {
        return "SECTION:" + normalized;
    }
    return normalized + ":" + entityId;
}

public static AccessPatchItemDto entityUpsert(
        String entityType,
        Long entityId,
        String revision,
        java.util.Map<String, Object> payload,
        java.util.Map<String, Object> impact
) {
    return AccessPatchItemDto.builder()
            .itemId(java.util.UUID.randomUUID().toString())
            .kind("ENTITY_UPSERT")
            .entityType(entityType)
            .entityId(entityId)
            .revision(revision)
            .payload(payload)
            .impact(impact)
            .build();
}

public static AccessPatchItemDto sectionReplace(
        String entityType,
        String revision,
        java.util.Map<String, Object> payload,
        java.util.Map<String, Object> impact
) {
    return AccessPatchItemDto.builder()
            .itemId(java.util.UUID.randomUUID().toString())
            .kind("SECTION_REPLACE")
            .entityType(entityType)
            .entityId(null)
            .revision(revision)
            .payload(payload)
            .impact(impact)
            .build();
}

public AccessPatchBundleDto resolveBundle(AccessPatchChangeRefDto changeRef, Long gymId) {
    AccessPatchChangeRefDto normalized = normalizeChangeRef(changeRef);
    String entityType = String.valueOf(normalized.getEntityType()).trim().toUpperCase();
    String revision = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).toString();

    return switch (entityType) {
        case "ACTIVE_MEMBERSHIP" -> buildMembershipBundle(normalized, gymId, revision);
        case "GYM_DEVICE" -> buildDeviceBundle(normalized, gymId, revision);
        case "SETTINGS" -> buildSettingsBundle(gymId, revision);
        case "CREDENTIALS" -> buildCredentialsBundle(gymId, revision);
        case "INFRASTRUCTURES" -> buildInfrastructureBundle(gymId, revision);
        case "MEMBERSHIP_TYPE" -> buildMembershipTypeBundle(gymId, revision);
        default -> AccessPatchBundleDto.builder()
                .schemaVersion(1)
                .bundleId(java.util.UUID.randomUUID().toString())
                .gymId(gymId)
                .generatedAt(revision)
                .items(java.util.List.of())
                .requiresReconcile(true)
                .build();
    };
}
```

- [ ] **Step 4: Make the controller call the real service**

In `GymAccessController.java`, inject and call the service:

```java
private final AccessPatchBundleService accessPatchBundleService;

public GymAccessController(..., AccessPatchBundleService accessPatchBundleService, ...) {
    this.accessPatchBundleService = accessPatchBundleService;
}

@PostMapping("/manager/gym/access/v1/patch-bundles/resolve")
public ResponseEntity<AccessPatchBundleDto> resolveFastPatchBundle(
        @RequestBody AccessPatchChangeRefDto changeRef,
        HttpServletRequest httpRequest
) {
    MainAccountModel sender = Utils.requireGymAccount(httpRequest, jwtService, mainAccountRepository);
    return ResponseEntity.ok(accessPatchBundleService.resolveBundle(changeRef, sender.getGym().getId()));
}
```

- [ ] **Step 5: Run focused backend tests**

Run:

```bash
cd D:\projects\MonClub\monclub_backend
mvn -q -Dtest=GymAccessControllerFastPatchBundleTest,GymAccessControllerDeltaWatermarkTest,GymAccessControllerMembersVersionTest test
```

Expected: PASS

- [ ] **Step 6: Commit the backend resolver**

```bash
cd D:\projects\MonClub\monclub_backend
git add src/main/java/com/tpjava/tpjava/Services/AccessPatchBundleService.java src/main/java/com/tpjava/tpjava/Controllers/GymAccessController.java src/test/java/com/tpjava/tpjava/Controllers/GymAccessControllerFastPatchBundleTest.java
git commit -m "feat(access): resolve canonical fast patch bundles"
```

---

## Task 3: Access Fast-Patch Journals, Revision Checks, and Section Apply Helpers

**Files:**
- Create: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\fast_patch.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\db.py`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_fast_patch_db.py`

- [ ] **Step 1: Write the failing storage and stale-revision tests**

Create `tests/test_fast_patch_db.py`:

```python
from __future__ import annotations


def test_record_fast_patch_bundle_is_idempotent(tmp_path, monkeypatch):
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()

    assert db_module.record_fast_patch_bundle(bundle_id="bundle-1", generated_at="2026-04-12T12:00:00Z") is True
    assert db_module.record_fast_patch_bundle(bundle_id="bundle-1", generated_at="2026-04-12T12:00:00Z") is False


def test_should_apply_fast_patch_item_rejects_older_revision(tmp_path, monkeypatch):
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()

    db_module.save_fast_patch_revision(patch_key="ACTIVE_MEMBERSHIP:9", revision="2026-04-12T12:00:02Z")

    assert db_module.should_apply_fast_patch_item(
        patch_key="ACTIVE_MEMBERSHIP:9",
        revision="2026-04-12T12:00:01Z",
    ) is False


def test_apply_membership_entity_upsert_updates_sync_users(tmp_path, monkeypatch):
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()

    bundle = {
        "bundleId": "bundle-2",
        "generatedAt": "2026-04-12T12:00:03Z",
        "items": [
            {
                "kind": "ENTITY_UPSERT",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": 5,
                "revision": "2026-04-12T12:00:03Z",
                "payload": {
                    "activeMembershipId": 5,
                    "membershipId": 4,
                    "userId": 7,
                    "fullName": "Mohamed Example",
                    "fingerprints": [],
                },
            }
        ],
    }

    result = db_module.apply_fast_patch_bundle(bundle)
    users = db_module.list_sync_users()

    assert result["applied"] == 1
    assert [u["activeMembershipId"] for u in users] == [5]


def test_apply_section_replace_updates_credentials_snapshot(tmp_path, monkeypatch):
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()

    bundle = {
        "bundleId": "bundle-3",
        "generatedAt": "2026-04-12T12:00:04Z",
        "items": [
            {
                "kind": "SECTION_REPLACE",
                "entityType": "CREDENTIALS",
                "revision": "2026-04-12T12:00:04Z",
                "payload": {
                    "gymAccessCredentials": [
                        {"id": 1, "accountId": 3, "enabled": True, "secretHex": "01020304", "grantedActiveMembershipIds": [5]}
                    ]
                },
            }
        ],
    }

    result = db_module.apply_fast_patch_bundle(bundle)
    creds = db_module.list_sync_gym_access_credentials()

    assert result["applied"] == 1
    assert len(creds) == 1
    assert creds[0]["accountId"] == 3
```

- [ ] **Step 2: Run the DB tests to confirm they fail**

Run:

```bash
cd C:\Users\mohaa\Desktop\monclub_access_python
python -m pytest tests/test_fast_patch_db.py -q
```

Expected: FAIL with missing fast-patch helpers

- [ ] **Step 3: Add fast-patch key helpers and journal tables**

Create `app/core/fast_patch.py`:

```python
from __future__ import annotations

from typing import Any


def patch_key(entity_type: str, entity_id: Any | None) -> str:
    normalized = str(entity_type or "").strip().upper()
    if normalized in {"SETTINGS", "CREDENTIALS", "INFRASTRUCTURES", "MEMBERSHIP_TYPE"}:
        return f"SECTION:{normalized}"
    return f"{normalized}:{entity_id}"
```

In `db.py`, add the two tables inside `init_db()`:

```python
conn.execute(
    """
    CREATE TABLE IF NOT EXISTS fast_patch_bundles (
        bundle_id TEXT PRIMARY KEY,
        generated_at TEXT NOT NULL,
        applied_at TEXT NOT NULL
    )
    """
)
conn.execute(
    """
    CREATE TABLE IF NOT EXISTS fast_patch_revisions (
        patch_key TEXT PRIMARY KEY,
        revision TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """
)
```

- [ ] **Step 4: Implement bundle ledger, revision checks, and transactional apply**

Add to `db.py`:

```python
def record_fast_patch_bundle(*, bundle_id: str, generated_at: str) -> bool:
    with get_conn() as conn:
        row = conn.execute("SELECT 1 FROM fast_patch_bundles WHERE bundle_id = ?", (bundle_id,)).fetchone()
        if row:
            return False
        conn.execute(
            "INSERT INTO fast_patch_bundles (bundle_id, generated_at, applied_at) VALUES (?, ?, ?)",
            (bundle_id, generated_at, now_iso()),
        )
        conn.commit()
        return True


def save_fast_patch_revision(*, patch_key: str, revision: str) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO fast_patch_revisions (patch_key, revision, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(patch_key) DO UPDATE SET
                revision = excluded.revision,
                updated_at = excluded.updated_at
            """,
            (patch_key, revision, now_iso()),
        )
        conn.commit()


def should_apply_fast_patch_item(*, patch_key: str, revision: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT revision FROM fast_patch_revisions WHERE patch_key = ?",
            (patch_key,),
        ).fetchone()
    return row is None or str(revision or "") >= str(row[0] or "")


def apply_fast_patch_bundle(bundle: dict) -> dict:
    from app.core.fast_patch import patch_key

    bundle_id = str(bundle.get("bundleId") or "").strip()
    generated_at = str(bundle.get("generatedAt") or now_iso())
    if not record_fast_patch_bundle(bundle_id=bundle_id, generated_at=generated_at):
        return {"applied": 0, "ignored": "duplicate_bundle"}

    applied = 0
    with get_conn() as conn:
        cur = conn.cursor()
        for item in list(bundle.get("items") or []):
            key = patch_key(item.get("entityType"), item.get("entityId"))
            revision = str(item.get("revision") or "")
            if not should_apply_fast_patch_item(patch_key=key, revision=revision):
                continue
            _apply_fast_patch_item(cur, item)
            cur.execute(
                """
                INSERT INTO fast_patch_revisions (patch_key, revision, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(patch_key) DO UPDATE SET
                    revision = excluded.revision,
                    updated_at = excluded.updated_at
                """,
                (key, revision, now_iso()),
            )
            applied += 1
        conn.commit()
    return {"applied": applied, "ignored": None}
```

- [ ] **Step 5: Run the focused Access DB tests**

Run:

```bash
cd C:\Users\mohaa\Desktop\monclub_access_python
python -m pytest tests/test_fast_patch_db.py -q
```

Expected: PASS

- [ ] **Step 6: Commit the Access DB layer**

```bash
cd C:\Users\mohaa\Desktop\monclub_access_python
git add app/core/fast_patch.py app/core/db.py tests/test_fast_patch_db.py
git commit -m "feat(access): add fast patch journals and transactional db apply"
```

---

## Task 4: Access Local API Receiver, Runtime Actions, and Hot-Cache Invalidation

**Files:**
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\api\local_access_api_v2.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\ui\app.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\realtime_agent.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\ultra_engine.py`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_fast_patch_api.py`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_fast_patch_runtime.py`

- [ ] **Step 1: Write failing API and runtime tests**

Create `tests/test_fast_patch_api.py`:

```python
from __future__ import annotations

from types import SimpleNamespace


def test_sync_fast_patch_bundle_calls_app_apply(monkeypatch):
    from app.api import local_access_api_v2 as api_module

    sent = []
    called = []
    ctx = SimpleNamespace(
        body=lambda: {"bundleId": "bundle-1", "generatedAt": "2026-04-12T12:00:00Z", "items": []},
        app=SimpleNamespace(apply_fast_patch_bundle=lambda bundle: called.append(bundle) or {"ok": True}),
        send_json=lambda status, payload: sent.append((status, payload)),
    )

    api_module._handle_sync_fast_patch_bundle(ctx)

    assert called[0]["bundleId"] == "bundle-1"
    assert sent[0][0] == 200
```

Create `tests/test_fast_patch_runtime.py`:

```python
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock


def test_apply_fast_patch_bundle_invalidates_caches_and_requests_ultra_sync(monkeypatch):
    import app.ui.app as app_module

    invalidate = MagicMock()
    ultra_sync = MagicMock()

    monkeypatch.setattr("app.core.db.apply_fast_patch_bundle", lambda bundle: {"applied": 1, "ignored": None})
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", invalidate)

    app = SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(side_effect=lambda **kwargs: ultra_sync(kwargs)),
        request_sync_now=MagicMock(),
    )

    bundle = {
        "bundleId": "bundle-1",
        "generatedAt": "2026-04-12T12:00:00Z",
        "items": [
            {
                "kind": "ENTITY_UPSERT",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": 9,
                "revision": "2026-04-12T12:00:00Z",
                "impact": {"affectedMemberIds": [9], "affectedDeviceIds": [7]},
            }
        ],
        "requiresReconcile": True,
    }

    result = app_module.MainApp.apply_fast_patch_bundle(app, bundle)

    assert result["ok"] is True
    invalidate.assert_called_once()
    app.reset_runtime_fast_patch_caches.assert_called_once()
    app._request_running_ultra_sync.assert_called_once()
    app.request_sync_now.assert_called_once()
```

- [ ] **Step 2: Run the tests to confirm they fail**

Run:

```bash
cd C:\Users\mohaa\Desktop\monclub_access_python
python -m pytest tests/test_fast_patch_api.py tests/test_fast_patch_runtime.py -q
```

Expected: FAIL with missing endpoint / app method

- [ ] **Step 3: Add the new localhost route and handler**

In `local_access_api_v2.py`, add the route:

```python
router.add("POST", "/api/v2/sync/fast-patch-bundle", _handle_sync_fast_patch_bundle)
```

Add the handler:

```python
def _handle_sync_fast_patch_bundle(ctx: _Ctx) -> None:
    bundle = ctx.body()
    result = ctx.app.apply_fast_patch_bundle(bundle)
    status = 200 if result.get("ok") else 409
    ctx.send_json(status, result)
```

- [ ] **Step 4: Implement the MainApp fast-patch executor and cache reset hooks**

In `app.py`, add:

```python
def reset_runtime_fast_patch_caches(self) -> None:
    try:
        if self._agent_engine and hasattr(self._agent_engine, "reset_fast_patch_caches"):
            self._agent_engine.reset_fast_patch_caches()
    except Exception:
        self.logger.warning("[FastPatch] failed to reset agent caches", exc_info=True)
    try:
        if self._ultra_engine and hasattr(self._ultra_engine, "reset_fast_patch_caches"):
            self._ultra_engine.reset_fast_patch_caches()
    except Exception:
        self.logger.warning("[FastPatch] failed to reset ULTRA caches", exc_info=True)


def apply_fast_patch_bundle(self, bundle: dict) -> dict:
    from app.core.db import apply_fast_patch_bundle, invalidate_sync_cache

    db_result = apply_fast_patch_bundle(bundle)
    if db_result.get("ignored") == "duplicate_bundle":
        return {"ok": True, "duplicate": True, **db_result}

    invalidate_sync_cache()
    self.reset_runtime_fast_patch_caches()

    affected_member_ids = {
        int(member_id)
        for item in list(bundle.get("items") or [])
        for member_id in list((item.get("impact") or {}).get("affectedMemberIds") or [])
        if member_id is not None
    }
    if affected_member_ids or any(
        str((item.get("entityType") or "")).upper() == "ACTIVE_MEMBERSHIP"
        for item in list(bundle.get("items") or [])
    ):
        self._request_running_ultra_sync(
            refresh={"members": True, "devices": False},
            changed_ids=affected_member_ids,
            reason="FAST_PATCH_BUNDLE",
        )

    self.request_sync_now(
        trigger_source="FAST_PATCH_BUNDLE",
        run_type="TRIGGERED",
        trigger_hint={"reason": "fast_patch_bundle"},
    )
    return {"ok": True, **db_result}
```

In `realtime_agent.py` and `ultra_engine.py`, add a simple `reset_fast_patch_caches()` method that clears their cached user and credential snapshots.

- [ ] **Step 5: Run the focused Access fast-patch tests**

Run:

```bash
cd C:\Users\mohaa\Desktop\monclub_access_python
python -m pytest tests/test_fast_patch_db.py tests/test_fast_patch_api.py tests/test_fast_patch_runtime.py -q
```

Expected: PASS

- [ ] **Step 6: Commit the Access API/runtime layer**

```bash
cd C:\Users\mohaa\Desktop\monclub_access_python
git add app/api/local_access_api_v2.py app/ui/app.py app/core/realtime_agent.py app/core/ultra_engine.py tests/test_fast_patch_api.py tests/test_fast_patch_runtime.py
git commit -m "feat(access): receive fast patch bundles and execute runtime actions"
```

---

## Task 5: Dashboard Resolve-and-Dispatch Service and Mutation Wiring

**Files:**
- Create: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\services\AccessPatchDispatchService.ts`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\services\LocalAccessService.ts`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\ActiveMembership\view\active-membership-form.tsx`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\ActiveMembership\view\active-membership-fingerprints-dialog.tsx`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\GymDevices\view\gym-devices-view.tsx`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\UserAccount\GymAccessSoftwareSettingsView.tsx`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\GymInfrastructure\view\gym-infrastructure-view.tsx`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\Membership\view\membership-view.tsx`

- [ ] **Step 1: Add the shared dispatcher service**

Create `AccessPatchDispatchService.ts`:

```ts
import api from 'src/api/axiosConfig';
import { localServiceFetch, triggerLocalAccessSync } from './LocalAccessService';

export type AccessChangeRef = {
  entityType:
    | 'ACTIVE_MEMBERSHIP'
    | 'FINGERPRINT'
    | 'GYM_DEVICE'
    | 'SETTINGS'
    | 'CREDENTIALS'
    | 'INFRASTRUCTURES'
    | 'MEMBERSHIP_TYPE';
  entityId?: number | null;
  relatedActiveMembershipId?: number | null;
  operation: 'CREATE' | 'UPDATE' | 'DELETE';
};

export async function resolveAndDispatchAccessPatch(changeRef: AccessChangeRef): Promise<void> {
  try {
    const response = await api.post('/manager/gym/access/v1/patch-bundles/resolve', {
      schemaVersion: 1,
      changeRef,
      source: 'DASHBOARD',
      requestedAt: new Date().toISOString(),
    });

    await localServiceFetch('/api/v2/sync/fast-patch-bundle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(response.data),
    });
  } catch {
    // Fast path is best-effort; fallback sync still runs below.
  }

  void triggerLocalAccessSync({
    entityType: changeRef.entityType === 'FINGERPRINT' ? 'ACTIVE_MEMBERSHIP' : (changeRef.entityType as any),
    entityId: changeRef.relatedActiveMembershipId ?? changeRef.entityId ?? undefined,
    operation: changeRef.operation,
    priority: 'HIGH',
  });
}
```

- [ ] **Step 2: Extend `LocalAccessService.ts` with a bundle POST helper**

Add:

```ts
export async function postFastPatchBundle(bundle: unknown): Promise<void> {
  const candidates = buildCandidates(getLocalBase());
  for (const base of candidates) {
    try {
      const res = await fetch(`${base}/api/v2/sync/fast-patch-bundle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bundle),
      });
      if (res.ok) return;
    } catch {
      // Best-effort localhost dispatch
    }
  }
}
```

- [ ] **Step 3: Replace direct `triggerLocalAccessSync` calls in membership, fingerprint, and device views**

In `active-membership-form.tsx`, replace:

```ts
void triggerLocalAccessSync({
  entityType: 'ACTIVE_MEMBERSHIP',
  entityId: editTarget.id ?? undefined,
  operation: 'UPDATE',
  priority: 'HIGH',
});
```

with:

```ts
void resolveAndDispatchAccessPatch({
  entityType: 'ACTIVE_MEMBERSHIP',
  entityId: editTarget.id ?? undefined,
  operation: 'UPDATE',
});
```

In `active-membership-fingerprints-dialog.tsx`, use:

```ts
void resolveAndDispatchAccessPatch({
  entityType: 'FINGERPRINT',
  entityId: fingerprintId ?? undefined,
  relatedActiveMembershipId: activeMembershipId,
  operation: 'DELETE',
});
```

In `gym-devices-view.tsx`, use:

```ts
void resolveAndDispatchAccessPatch({
  entityType: 'GYM_DEVICE',
  entityId: createdOrUpdatedId,
  operation: isEdit ? 'UPDATE' : 'CREATE',
});
```

- [ ] **Step 4: Wire settings, infrastructure, and membership-type success flows**

In `GymAccessSoftwareSettingsView.tsx`, after successful save:

```ts
void resolveAndDispatchAccessPatch({
  entityType: 'SETTINGS',
  entityId: Number(savedSettings?.id ?? 0) || undefined,
  operation: 'UPDATE',
});
```

In `gym-infrastructure-view.tsx`, after successful create, update, or delete:

```ts
void resolveAndDispatchAccessPatch({
  entityType: 'INFRASTRUCTURES',
  entityId: infraId ?? undefined,
  operation,
});
```

In `membership-view.tsx`, after successful create, update, or delete:

```ts
void resolveAndDispatchAccessPatch({
  entityType: 'MEMBERSHIP_TYPE',
  entityId: membershipId ?? undefined,
  operation,
});
```

**Credential note:** keep `CREDENTIALS` support in `AccessPatchDispatchService.ts`, but do not invent a fake dashboard callsite. No dedicated credential mutation page exists in the current dashboard repo.

- [ ] **Step 5: Run dashboard build verification**

Run:

```bash
cd C:\Users\mohaa\Desktop\mon_club_dashboard
npm run build
```

Expected: PASS

- [ ] **Step 6: Commit the dashboard wiring**

```bash
cd C:\Users\mohaa\Desktop\mon_club_dashboard
git add src/sections/services/AccessPatchDispatchService.ts src/sections/services/LocalAccessService.ts src/sections/ActiveMembership/view/active-membership-form.tsx src/sections/ActiveMembership/view/active-membership-fingerprints-dialog.tsx src/sections/GymDevices/view/gym-devices-view.tsx src/sections/UserAccount/GymAccessSoftwareSettingsView.tsx src/sections/GymInfrastructure/view/gym-infrastructure-view.tsx src/sections/Membership/view/membership-view.tsx
git commit -m "feat(dashboard): resolve and dispatch fast patch bundles after access mutations"
```

---

## Task 6: Cross-Repo Verification and Regression Pass

**Files:**
- Modify as needed based on failures from Tasks 1–5

- [ ] **Step 1: Run Access fast-patch tests and existing sync/device regressions**

Run:

```bash
cd C:\Users\mohaa\Desktop\monclub_access_python
python -m pytest tests/test_fast_patch_db.py tests/test_fast_patch_api.py tests/test_fast_patch_runtime.py tests/test_sync_hot_path_optimizations.py tests/test_differential_device_push.py tests/test_ultra_sync_scheduler.py -q
```

Expected: PASS

- [ ] **Step 2: Run the focused backend test suite**

Run:

```bash
cd D:\projects\MonClub\monclub_backend
mvn -q -Dtest=GymAccessControllerFastPatchBundleTest,GymAccessControllerDeltaWatermarkTest,GymAccessControllerMembersVersionTest test
```

Expected: PASS

- [ ] **Step 3: Run the dashboard build**

Run:

```bash
cd C:\Users\mohaa\Desktop\mon_club_dashboard
npm run build
```

Expected: PASS

- [ ] **Step 4: Manual end-to-end smoke test**

Manual checklist:

```text
1. Edit an active membership in dashboard.
2. Confirm backend mutation succeeds.
3. Confirm dashboard posts a fast patch bundle to localhost.
4. Confirm Access logs bundle receipt, bundle apply, cache invalidation, targeted sync trigger.
5. Scan the same member's QR or card immediately.
6. Confirm the local Access decision reflects the new data before waiting for normal sync.
7. Repeat for fingerprint delete, device edit, settings edit, infrastructure edit, and membership-type edit.
```

Expected: local Access reflects each change immediately, and fallback reconcile still runs afterward.

- [ ] **Step 5: Final commit(s) for verification-driven fixes**

```bash
cd C:\Users\mohaa\Desktop\monclub_access_python
git add -A
git commit -m "fix(access): address fast patch verification findings"

cd C:\Users\mohaa\Desktop\mon_club_dashboard
git add -A
git commit -m "fix(dashboard): address fast patch verification findings"

cd D:\projects\MonClub\monclub_backend
git add -A
git commit -m "fix(backend): address fast patch verification findings"
```

---

## Verification Checklist

- [ ] Backend resolves canonical bundles for `ACTIVE_MEMBERSHIP`, `FINGERPRINT`, `GYM_DEVICE`, `SETTINGS`, `CREDENTIALS`, `INFRASTRUCTURES`, and `MEMBERSHIP_TYPE`.
- [ ] Fingerprint change refs normalize into membership access patches.
- [ ] Dashboard mutation success paths resolve and forward fast patch bundles before fallback sync.
- [ ] Local Access rejects duplicate bundles by `bundleId`.
- [ ] Local Access rejects stale items by revision ledger.
- [ ] Fast patch updates only affected normalized tables, not the whole sync payload blob.
- [ ] `load_sync_cache()` and runtime verification caches are invalidated immediately after apply.
- [ ] Membership and fingerprint patches trigger targeted member push instead of blanket push.
- [ ] Device patches trigger targeted device reload or rescope behavior.
- [ ] Settings patches trigger the correct class of action: cache-only, service rebind, or controlled restart.
- [ ] Credential changes affect local TOTP and card verification immediately after patch apply.
- [ ] Background reconcile remains enabled and authoritative.
- [ ] Access, backend, and dashboard verification commands all pass.

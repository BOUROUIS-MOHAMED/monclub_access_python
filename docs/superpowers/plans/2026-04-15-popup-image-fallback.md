# Popup Image 3-Tier Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** When a member scans, the popup must try the active-membership image first, then fall back to the user profile image, then a placeholder.

**Architecture:** The Spring Boot `GymAccessController` currently sends only one resolved image URL (active-membership image). Add a second URL (user profile image, resolved via `MemberImageService.resolveProfileImageUrl`) into the sync DTO. Thread it through the Python sync cache, ULTRA/realtime engines, SSE notification payload, and into the React popup. The popup renders `userImage` first; on `onError` it swaps to `userProfileImage`; on a second `onError` it shows the existing initial-letter placeholder.

**Tech Stack:** Spring Boot (Java 17 + Lombok), Python 3 + SQLite, TypeScript/React (Tauri).

**3 Codebases:**
- `D:\projects\MonClub\monclub_backend` — Spring Boot
- `C:\Users\mohaa\Desktop\monclub_access_python` — Python access engine
- `C:\Users\mohaa\Desktop\monclub_access_python\tauri-ui` — React Tauri UI (lives inside the Python repo)

---

## Phase 1 — Spring Boot backend

### Task 1.1 — Add `userProfileImage` field to `ActiveMemberUserDto`

**File:** `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\DTO\ActiveMemberUserDto.java`

Append a new field at the end of the class (after `userImageStatus`):
```java
private String userProfileImage;
```

Lombok `@AllArgsConstructor` regenerates the constructor automatically. The new arg is appended to the constructor signature, so the existing `new ActiveMemberUserDto(...)` call site must be updated to pass the extra value.

### Task 1.2 — Add a batch resolver for user profile image URLs

**File:** `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Services\MemberImageService.java`

Add a new public method beside `resolveAccessImageUrlsBatch`:

```java
/**
 * Batch version of resolveProfileImageUrl for syncing all members in one query.
 * Mirrors {@link #resolveAccessImageUrlsBatch}: members without a USER_AVATAR
 * FileLink are absent from the result map — callers should fall back to
 * {@code user.getImage()} for those.
 */
public Map<Long, String> resolveProfileImageUrlsBatch(Collection<Long> userIds) {
    if (userIds == null || userIds.isEmpty()) {
        return Map.of();
    }
    List<FileLink> links = fileLinkRepository.findActiveByEntityIdsAndRole(
            MediaEntityType.USER,
            userIds,
            MediaFileRole.USER_AVATAR
    );
    Map<Long, String> result = new HashMap<>();
    for (FileLink link : links) {
        result.computeIfAbsent(link.getEntityId(), id -> resolveUrlFromStoredFile(link.getStoredFile()));
    }
    return result;
}
```

### Task 1.3 — Wire `userProfileImage` into `GymAccessController`

**File:** `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Controllers\GymAccessController.java`

Around lines 562-587 (inside the sync-data members section):

1. Build a list of distinct user IDs and call `memberImageService.resolveProfileImageUrlsBatch(...)`.
2. In the per-member `.map(am -> ...)` lambda, resolve `userProfileImage` as `profileUrlsByUserId.getOrDefault(am.getUser().getId(), am.getUser().getImage())`.
3. Pass it as the new last constructor arg to `new ActiveMemberUserDto(...)`.

### Task 1.4 — Build & run backend tests

```bash
cd /d/projects/MonClub/monclub_backend
./mvnw -q -DskipTests package
./mvnw test -Dtest=GymAccessController*
```

Confirm that tests still compile (the new constructor arg may break tests that build `ActiveMemberUserDto` directly).

---

## Phase 2 — Python (access engine)

### Task 2.1 — `app/core/db.py`: schema + INSERT + coercion

**File:** `C:\Users\mohaa\Desktop\monclub_access_python\app\core\db.py`

1. **Schema migration** (next to existing `_ensure_column` lines for `image_source`/`user_image_status`, around line 470):
   ```python
   _ensure_column(conn, "sync_users", "user_profile_image", "user_profile_image TEXT")
   ```

2. **Five INSERT-OR-REPLACE call sites** must add the new column + value:
   - Line 1699 (delta upsert)
   - Line 2471 (full sync)
   - Line 2892 (`_upsert_sync_user_row`)
   - Line 3173 (`save_sync_cache_delta` first INSERT)
   - Line 3320 (`save_sync_cache_delta` second INSERT)

   For each: append `, user_profile_image` to the column list, an extra `?` to the VALUES tuple, and `u.get("userProfileImage")` (or `member.get("userProfileImage")`) to the value tuple.

3. **`_users_content_hash` (line 3247)** — append `|{u.get('userProfileImage')}` so the hash detects changes to the profile image URL too. Also extend the SELECT at line 3272 + the `existing_as_dicts` builder at line 3286 with the new column and key.

4. **`_coerce_user_row_to_payload`** (line 3431-3450) — add:
   ```python
   "userProfileImage": g("userProfileImage", "user_profile_image"),
   ```

5. **`_projection_from_user`** offline-pending entries at lines 6601 and 6654 — add `"userProfileImage": user_src.get("userProfileImage")` (line 6601) / `"userProfileImage": None` (line 6654).

### Task 2.2 — `app/core/access_types.py`: dataclass field

Add to `NotificationRequest`:
```python
user_profile_image: str = ""
```

### Task 2.3 — `app/core/ultra_engine.py`: extract + thread through

For both `_handle_allow` (around line 793-839) and `_handle_totp_rescue` (around line 877-956):

1. Initialize `user_profile_image = ""`
2. Inside the `if isinstance(user, dict):` block add:
   ```python
   user_profile_image = str(user.get("userProfileImage", "") or "")
   ```
3. Pass `user_profile_image=user_profile_image` to `_enqueue_notification`.

In `_enqueue_notification` signature (line 1061-1109):
1. Add `user_profile_image: str = ""` keyword arg.
2. Pass `user_profile_image=user_profile_image` to `NotificationRequest(...)`.

In the DENY path at line 1034-1045, add `user_profile_image=""`.

### Task 2.4 — `app/core/realtime_agent.py`: extract + thread through + SSE payload

Around line 1190-1276:

1. Add: `user_profile_image = _safe_str((user or {}).get("userProfileImage"), "") if isinstance(user, dict) else ""`.
2. Pass `user_profile_image=user_profile_image` to `NotificationRequest(...)`.

In `_popup_payload_from_request` (around line 388-411), add:
```python
"userProfileImage": req.user_profile_image,
```

---

## Phase 3 — TypeScript / React popup

### Task 3.1 — `tauri-ui/src/api/types.ts`: extend `PopupEvent`

After `userImageStatus?: string;` add:
```typescript
/** User profile image URL (USER_AVATAR), used as fallback when userImage fails or is empty */
userProfileImage?: string;
```

### Task 3.2 — `tauri-ui/src/pages/PopupWindow.tsx`: cascade fallback

1. In `toPopupEvent` add:
   ```typescript
   userProfileImage: String(raw?.userProfileImage ?? ""),
   ```

2. Rework `resolveImage` to track a fallback chain:
   ```typescript
   const resolveImage = useCallback((evt: PopupEvent) => {
     if (!evt.popupShowImage) {
       setImageChain([]);
       setImgSrc(null);
       return;
     }
     const candidates: string[] = [];
     const am = (evt.userImage || evt.imagePath || "").trim();
     const profile = (evt.userProfileImage || "").trim();
     if (am) candidates.push(am);
     if (profile && profile !== am) candidates.push(profile);
     setImageChain(candidates);
     setImgSrc(candidates[0] ? toCacheUrl(candidates[0]) : null);
   }, []);
   ```
   where `toCacheUrl` is the existing data-URL/proxy logic, `imageChain` is a new ref-or-state holding the remaining candidates, and the `<img onError>` advances to the next candidate or sets `imgSrc=null`.

3. Reset `imageChain` whenever a new event lands (in `showEvent`).

### Task 3.3 — `tauri-ui/src/components/NotificationPopup.tsx`: same cascade

The dev-mode component currently only uses a single URL. Mirror the same fallback chain (use a small `useState` for the active index). The `<Box component="img" onError>` advances to the next candidate before falling back to the placeholder.

### Task 3.4 — `tauri-ui/src/components/NotificationDrawer.tsx`: cascade in avatar

The drawer avatar at line 53 should likewise prefer `userImage`, fall back to `userProfileImage`. Simpler — just compute `src={evt.userImage || evt.userProfileImage || undefined}`.

---

## Phase 4 — Verification

1. Run `pytest tests/` in the Python repo (smoke). The hash function & coercion changes are exercised by sync tests.
2. Restart the Python core and the Tauri UI in dev mode.
3. Pick a member with **only a profile image** (no AM image set in admin dashboard) and have them scan a card.
4. Confirm the popup shows the profile image (not the placeholder).
5. Pick a member with **neither** image and confirm the placeholder still shows.
6. Pick a member with **both** images and confirm the AM image shows (not profile).

---

## Out of scope

- Backfilling existing sync caches — old data has `user_profile_image = NULL` until the next backend sync, which is fine (graceful degradation to current behavior).
- Changing how `imageSource` chip is computed (still based on backend value).
- Image preloading / prefetching.

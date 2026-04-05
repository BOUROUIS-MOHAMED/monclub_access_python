# Access Popup Image Flags Design

**Goal:** Surface two image-related flags in the door-scan popup — a "Profile photo" label when no gym-specific image is set, and an "Image change required" warning when the admin has flagged the member.

**Architecture:** Two new fields (`imageSource`, `userImageStatus`) travel from the backend sync endpoint through the SQLite cache, the Python ultra engine, the SSE notification payload, and finally into the React popup component. No live API calls are needed at scan time — everything is pre-loaded in the sync cache.

**Tech Stack:** Python 3, SQLite, Spring Boot backend (already modified), TypeScript/React, Material-UI v5.

---

## 1. Backend — `ActiveMemberUserDto`

Both fields already exist on the domain models from the member image verification feature:
- `ActiveMembership.imageSource` — `ImageSource` enum (`GYM_UPLOAD`, `GYM_CAPTURE`, `GYM_GALLERY`, `PROFILE_BORROWED`)
- `UserModel.userImageStatus` — `UserImageStatus` enum (`OK`, `REQUIRED_CHANGE`)

**Change:** Add two fields to `ActiveMemberUserDto` and populate them in `GymAccessController` where the DTO is constructed (line ~517):

```java
// New fields on ActiveMemberUserDto:
private final String imageSource;       // nullable — null means no image was ever assigned
private final String userImageStatus;   // never null — defaults to "OK"

// In GymAccessController, inside the .map(am -> ...) lambda:
am.getImageSource() != null ? am.getImageSource().name() : null,
am.getUser().getUserImageStatus().name()
```

The existing `image` field at position 528 stays unchanged — it already contains the resolved URL via `memberImageService.resolveAccessImageUrl(am)`.

---

## 2. Python — SQLite Cache (`app/core/db.py`)

Add two TEXT columns to `sync_users`. Use `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` for safe migration (SQLite supports this in 3.37+, and the app's schema init runs on every startup):

```sql
ALTER TABLE sync_users ADD COLUMN IF NOT EXISTS image_source TEXT;
ALTER TABLE sync_users ADD COLUMN IF NOT EXISTS user_image_status TEXT;
```

Both columns are nullable. A `NULL` value for `user_image_status` is treated as `OK`.

---

## 3. Python — Sync Population (`app/core/device_sync.py`)

When inserting/updating a `sync_users` row from the backend response, map the new fields:

```python
image_source = member.get("imageSource")          # may be None
user_image_status = member.get("userImageStatus")  # may be None, treat as "OK"
```

Include them in the `INSERT OR REPLACE` statement alongside the existing columns.

---

## 4. Python — Ultra Engine (`app/core/ultra_engine.py`)

In both `_handle_allow()` and `_handle_totp_rescue()`, after the existing `user_image` extraction, read the two new fields:

```python
image_source = str(user.get("image_source", "") or "")
user_image_status = str(user.get("user_image_status", "") or "")
```

Pass them to `NotificationRequest`:

```python
NotificationRequest(
    ...
    image_source=image_source,
    user_image_status=user_image_status,
)
```

---

## 5. Python — `NotificationRequest` (`app/core/access_types.py`)

Add two new optional fields to the dataclass:

```python
@dataclass
class NotificationRequest:
    ...
    image_source: str = ""         # e.g. "PROFILE_BORROWED", "GYM_UPLOAD", etc.
    user_image_status: str = ""    # e.g. "REQUIRED_CHANGE", "OK"
```

---

## 6. Python — SSE Payload (`app/core/realtime_agent.py`)

In `_popup_payload_from_request()`, add the two new fields to the returned dict:

```python
"imageSource": req.image_source,
"userImageStatus": req.user_image_status,
```

---

## 7. Tauri UI — Types (`tauri-ui/src/api/types.ts`)

Add two fields to the `PopupEvent` interface:

```typescript
imageSource: string;       // "PROFILE_BORROWED" | "GYM_UPLOAD" | "GYM_CAPTURE" | "GYM_GALLERY" | ""
userImageStatus: string;   // "REQUIRED_CHANGE" | "OK" | ""
```

---

## 8. Tauri UI — Popup Component (`tauri-ui/src/components/NotificationPopup.tsx`)

Add two chips below the member photo. Each chip is only rendered when its condition is true:

**"Profile photo" chip** — shown when `imageSource === 'PROFILE_BORROWED'`:
- MUI `<Chip>` with `size="small"`, `color="default"` (muted grey)
- Label: `"Profile photo — no gym image set"`
- Icon: `PersonIcon`
- Informational only, no interaction

**"Image change required" chip** — shown when `userImageStatus === 'REQUIRED_CHANGE'`:
- MUI `<Chip>` with `size="small"`, `color="warning"`
- Label: `"Image change required"`
- Icon: `WarningAmberIcon`
- Informational only, no interaction

Both chips are stacked in a `<Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, mt: 1 }}>` below the photo. Normal scans (gym image, `OK` status) render nothing extra.

---

## 9. Error Handling & Edge Cases

- **`imageSource` is null/empty:** No chip rendered — treated as a gym image or unknown source.
- **`userImageStatus` is null/empty:** No chip rendered — treated as `OK`.
- **Backend not yet redeployed:** Old sync data won't have the new fields; both columns will be `NULL` → no chips shown. Graceful degradation.
- **SQLite migration:** `ADD COLUMN IF NOT EXISTS` is idempotent — safe to run on every startup against an existing database.

---

## 10. Out of Scope

- Blocking access based on `userImageStatus` (member still gets in normally).
- Showing `imageRateLimitRemainingDays` in the popup.
- Any changes to the fingerprint, TOTP, or card scan logic.
- Changes to the `local_access_api_v1.py` (legacy, not used).

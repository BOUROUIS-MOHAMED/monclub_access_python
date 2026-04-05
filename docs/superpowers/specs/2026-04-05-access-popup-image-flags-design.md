# Access Popup Image Flags Design

**Goal:** Surface two image-related flags in the door-scan popup — a "Profile photo" label when no gym-specific image is set, and an "Image change required" warning when the admin has flagged the member.

**Architecture:** Two new fields (`imageSource`, `userImageStatus`) travel from the backend sync endpoint through the SQLite cache, a coercion helper, the Python ultra engine, the SSE notification payload, and finally into both React popup components. No live API calls are needed at scan time — everything is pre-loaded in the sync cache.

**Tech Stack:** Python 3, SQLite, Spring Boot backend (already modified), TypeScript/React, Material-UI v5, Tauri.

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

The existing `image` field stays unchanged — it already contains the resolved URL via `memberImageService.resolveAccessImageUrl(am)`.

---

## 2. Python — SQLite Cache (`app/core/db.py`)

**Two changes in `db.py`:**

### 2a. Add columns via `_ensure_column` (schema migration)

The codebase uses `_ensure_column(conn, table, col_name, col_definition)` — a helper that checks `PRAGMA table_info` first and only runs `ALTER TABLE ... ADD COLUMN` if the column is absent. This works on all SQLite versions. Add these two calls next to the existing `_ensure_column` block (lines 231–234):

```python
_ensure_column(conn, "sync_users", "image_source",      "image_source TEXT")
_ensure_column(conn, "sync_users", "user_image_status", "user_image_status TEXT")
```

Do **not** use raw `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` — that requires SQLite 3.37+ and the codebase deliberately avoids it.

### 2b. Update `_coerce_user_row_to_payload` (critical intermediary)

All SQLite rows are passed through `_coerce_user_row_to_payload()` (lines 1906–1947) before reaching the engine. This function builds a fixed-key dict from the raw row. The new columns must be added here, or `ultra_engine.py`'s `user.get(...)` calls will always return `None`:

```python
# Inside _coerce_user_row_to_payload, alongside the existing "image" mapping:
"imageSource":     g("imageSource", "image_source"),
"userImageStatus": g("userImageStatus", "user_image_status"),
```

These fields will then be accessible in the engine as camelCase keys (`imageSource`, `userImageStatus`).

---

## 3. Python — Sync Population (`app/core/db.py`)

There are **two** `INSERT OR REPLACE INTO sync_users` statements that must both be updated:

- **`save_sync_cache`** (~line 1545) — full sync path
- **`save_sync_cache_delta`** (~line 1819) — delta sync path

In both statements, add the two new columns and their values:

```python
# Column list addition:
..., image_source, user_image_status

# Values addition (from backend response member dict):
member.get("imageSource"),       # may be None
member.get("userImageStatus"),   # may be None, treated as "OK" downstream
```

Missing the delta path would cause the flags to silently disappear after incremental syncs.

---

## 4. Python — Ultra Engine (`app/core/ultra_engine.py`)

After the coercion step, the `user` dict contains camelCase keys. Update **both** `_handle_allow()` and `_handle_totp_rescue()` after their existing `user_image` extraction:

```python
# Both handlers read from the coerced dict (camelCase keys):
image_source      = str(user.get("imageSource",     "") or "")
user_image_status = str(user.get("userImageStatus", "") or "")
```

> **Note on `_handle_totp_rescue`:** The `user` dict in this handler comes from `verify_totp()` return value. Confirm that `verify_totp()` also returns a coerced dict (camelCase keys) — if it returns a raw SQLite row (snake_case), use `user.get("image_source")` instead.

**`_handle_allow` and `_handle_totp_rescue` call `_enqueue_notification(...)` which internally constructs `NotificationRequest`.** Add the two new parameters to `_enqueue_notification`'s signature and forward them:

```python
# _enqueue_notification signature — add two new keyword args:
def _enqueue_notification(self, ..., image_source: str = "", user_image_status: str = ""):
    ...
    req = NotificationRequest(
        ...
        image_source=image_source,
        user_image_status=user_image_status,
    )
```

Then call it from both handlers:

```python
self._enqueue_notification(
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

In `_popup_payload_from_request()`, add the two new fields:

```python
"imageSource":     req.image_source,
"userImageStatus": req.user_image_status,
```

> **Note:** `local_access_api_v2.py` imports and calls this same `_popup_payload_from_request` function for the ULTRA engine SSE path — no separate change is needed in `local_access_api_v2.py` since it shares the function.

---

## 7. Tauri UI — Types (`tauri-ui/src/api/types.ts`)

Add two **optional** fields to the `PopupEvent` interface. They are optional because old sync data and old backend responses will not include them (backward-compatible graceful degradation):

```typescript
imageSource?: string;      // "PROFILE_BORROWED" | "GYM_UPLOAD" | "GYM_CAPTURE" | "GYM_GALLERY" | undefined
userImageStatus?: string;  // "REQUIRED_CHANGE" | "OK" | undefined
```

---

## 8. Tauri UI — Popup Components

There are **two** popup components that must both be updated:

### 8a. `PopupWindow.tsx` (production — Tauri window)

This is the popup members actually see on the door screen. It has a `toPopupEvent()` deserialiser that maps raw SSE payload fields to the `PopupEvent` interface.

**In `toPopupEvent()`**, add mappings for the new fields with `""` defaults:

```typescript
imageSource:     raw.imageSource     ?? "",
userImageStatus: raw.userImageStatus ?? "",
```

**In the popup layout**, add the two chips below the member photo (right-side panel):

```tsx
{popup.imageSource === 'PROFILE_BORROWED' && (
  <Chip
    size="small"
    color="default"
    icon={<PersonIcon />}
    label="Profile photo — no gym image set"
    sx={{ mt: 1 }}
  />
)}
{popup.userImageStatus === 'REQUIRED_CHANGE' && (
  <Chip
    size="small"
    color="warning"
    icon={<WarningAmberIcon />}
    label="Image change required"
    sx={{ mt: 0.5 }}
  />
)}
```

Imports needed:
```typescript
import PersonIcon from '@mui/icons-material/Person';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
```

### 8b. `NotificationPopup.tsx` (dev-mode fallback)

Apply the same two chips in the same position (below the member photo). The chip code is identical to `PopupWindow.tsx` above.

---

## 9. Error Handling & Edge Cases

- **`imageSource` is null/empty/undefined:** No chip rendered — treated as unknown source (gym image or unset).
- **`userImageStatus` is null/empty/undefined:** No chip rendered — treated as `OK`.
- **Backend not yet redeployed / old sync data:** New columns will be `NULL` → coercion returns `""` → no chips shown. Fully backward-compatible.
- **`_ensure_column` is idempotent:** Safe to run on every startup against an existing database on any SQLite version the app already supports.

---

## 10. Out of Scope

- Blocking access based on `userImageStatus` (member still gets in normally).
- Showing `imageRateLimitRemainingDays` in the popup.
- Any changes to the fingerprint, TOTP, or card scan logic.
- Changes to `local_access_api_v1.py` (legacy, not active).

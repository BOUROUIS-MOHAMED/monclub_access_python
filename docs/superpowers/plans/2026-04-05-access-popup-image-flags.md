# Access Popup Image Flags Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface two image flags in the door-scan popup — a "Profile photo" label when no gym-specific image is set, and an "Image change required" warning — by threading `imageSource` and `userImageStatus` from the backend sync DTO through the Python cache, engine, SSE payload, and into both React popup components.

**Architecture:** Two new string fields travel in one direction only: backend sync response → SQLite cache → coercion helper → ultra engine → NotificationRequest → SSE payload → TypeScript interface → React chips. No live API calls at scan time — all data is pre-loaded during sync.

**Tech Stack:** Java/Spring Boot, Python 3/SQLite, TypeScript/React, Tailwind CSS (PopupWindow), MUI v5 (NotificationPopup)

---

## File Map

| File | Change |
|------|--------|
| `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\DTO\ActiveMemberUserDto.java` | Add 2 fields |
| `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Controllers\GymAccessController.java` | Populate new fields in DTO constructor (~line 498) |
| `app/core/db.py` | `_ensure_column` block + `_coerce_user_row_to_payload` + 2× INSERT OR REPLACE |
| `app/core/access_types.py` | `NotificationRequest` dataclass — 2 new fields |
| `app/core/ultra_engine.py` | `_handle_allow`, `_handle_totp_rescue`, `_enqueue_notification` |
| `app/core/realtime_agent.py` | `_popup_payload_from_request` |
| `tauri-ui/src/api/types.ts` | `PopupEvent` interface — 2 optional fields |
| `tauri-ui/src/pages/PopupWindow.tsx` | `toPopupEvent()` mappings + 2 Tailwind badges |
| `tauri-ui/src/components/NotificationPopup.tsx` | 2 MUI Chips below member image |

---

## Task 1: Backend — `ActiveMemberUserDto` + `GymAccessController`

**Files:**
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\DTO\ActiveMemberUserDto.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Controllers\GymAccessController.java:498-512`

- [ ] **Step 1: Add two fields to `ActiveMemberUserDto`**

  The class uses `@AllArgsConstructor` so adding fields changes the constructor signature. Add after the `image` field:

  ```java
  private String image;
  private List<ActiveMemberFingerprintDto> fingerprints;
  private String birthday;
  private String imageSource;       // nullable — null means no image was ever assigned
  private String userImageStatus;   // never null in practice — defaults to "OK"
  ```

- [ ] **Step 2: Populate the new fields in `GymAccessController`**

  The constructor call is at lines 498–512. The current last two args are `fpsByAmId.getOrDefault(am.getId(), List.of())` and `null` (birthday, set via setter below). Add two more args:

  ```java
  ActiveMemberUserDto dto = new ActiveMemberUserDto(
          am.getId(),
          am.getMembership().getId(),
          am.getUser().getId(),
          am.getUser().getFirstName() + " " + am.getUser().getLastName(),
          am.getUser().getPhone(),
          am.getUser().getEmail(),
          am.getStartDate() != null ? am.getStartDate().toString() : null,
          am.getEndDate() != null ? am.getEndDate().toString() : null,
          am.getCardId(),
          am.getSecondCardId(),
          memberImageService.resolveAccessImageUrl(am),
          fpsByAmId.getOrDefault(am.getId(), List.of()),
          null,  // birthday — set via setter below
          am.getImageSource() != null ? am.getImageSource().name() : null,
          am.getUser().getUserImageStatus() != null ? am.getUser().getUserImageStatus().name() : null
  );
  ```

- [ ] **Step 3: Verify it compiles**

  ```bash
  cd D:/projects/MonClub/monclub_backend
  ./mvnw compile -q
  ```
  Expected: `BUILD SUCCESS`

- [ ] **Step 4: Commit**

  ```bash
  git add src/main/java/com/tpjava/tpjava/Models/DTO/ActiveMemberUserDto.java \
          src/main/java/com/tpjava/tpjava/Controllers/GymAccessController.java
  git commit -m "feat(sync): add imageSource and userImageStatus to ActiveMemberUserDto"
  ```

- [ ] **Step 5: Push**

  ```bash
  git push origin main
  ```

---

## Task 2: Python `db.py` — Schema Migration + Coercion Helper

**Files:**
- Modify: `app/core/db.py` (lines 231–234 area and lines 1906–1947)

- [ ] **Step 1: Add two `_ensure_column` calls**

  After line 234 (`birthday TEXT`), before the `try` block at line 235:

  ```python
  _ensure_column(conn, "sync_users", "birthday",           "birthday TEXT")
  _ensure_column(conn, "sync_users", "image_source",       "image_source TEXT")
  _ensure_column(conn, "sync_users", "user_image_status",  "user_image_status TEXT")
  ```

  > The `birthday` line already exists — just add the two new lines directly below it.
  > Do NOT use `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` — `_ensure_column` is the project's pattern for SQLite < 3.37 compatibility.

- [ ] **Step 2: Add two entries to `_coerce_user_row_to_payload`**

  This function (lines 1906–1947) builds the camelCase dict that the engine reads. In the `return {}` block, add after the `"image"` entry:

  ```python
  return {
      ...
      "image":             g("image"),
      "imageSource":       g("imageSource", "image_source"),
      "userImageStatus":   g("userImageStatus", "user_image_status"),
      ...
  }
  ```

  If these are not added here, all `user.get("imageSource")` calls in the engine will return `None` regardless of what is in the database.

- [ ] **Step 3: Smoke-test the app starts without error**

  ```bash
  cd /c/Users/mohaa/Desktop/monclub_access_python
  python -c "from app.core.db import init_db; print('OK')"
  ```
  Expected: `OK`

- [ ] **Step 4: Commit**

  ```bash
  git add app/core/db.py
  git commit -m "feat(db): add image_source and user_image_status columns + coercion mapping"
  ```

---

## Task 3: Python `db.py` — Populate Columns in Both Sync Paths

**Files:**
- Modify: `app/core/db.py` (~lines 1543–1573 and ~lines 1817–1836)

> There are **two** `INSERT OR REPLACE INTO sync_users` statements — full sync (`save_sync_cache`) and delta sync (`save_sync_cache_delta`). Both must be updated. Missing the delta path means flags silently disappear after incremental syncs.

- [ ] **Step 1: Update `save_sync_cache` INSERT (~line 1543)**

  Add `image_source, user_image_status` to the column list and two values to the tuple:

  ```python
  cur.execute(
      """
      INSERT OR REPLACE INTO sync_users (
          user_id,
          active_membership_id,
          membership_id,
          full_name, phone, email, valid_from, valid_to,
          first_card_id, second_card_id, image,
          fingerprints_json,
          face_id, account_username_id, qr_code_payload, birthday,
          image_source, user_image_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      """,
      (
          u.get("userId"),
          am_id,
          m_id,
          u.get("fullName"),
          u.get("phone"),
          u.get("email"),
          u.get("validFrom"),
          u.get("validTo"),
          u.get("firstCardId"),
          u.get("secondCardId"),
          u.get("image"),
          json.dumps(fps, ensure_ascii=False),
          u.get("faceId"),
          u.get("accountUsernameId") or u.get("account_username_id"),
          u.get("qrCodePayload"),
          u.get("birthday"),
          u.get("imageSource"),       # may be None
          u.get("userImageStatus"),   # may be None, treated as "OK" downstream
      ),
  )
  ```

- [ ] **Step 2: Update `save_sync_cache_delta` INSERT (~line 1817)**

  Same addition — the delta INSERT currently has the same 16 columns/values. Add the same two at the end:

  ```python
  cur.execute(
      """
      INSERT OR REPLACE INTO sync_users (
          user_id, active_membership_id, membership_id,
          full_name, phone, email, valid_from, valid_to,
          first_card_id, second_card_id, image,
          fingerprints_json, face_id, account_username_id, qr_code_payload, birthday,
          image_source, user_image_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
          u.get("imageSource"),
          u.get("userImageStatus"),
      ),
  )
  ```

- [ ] **Step 3: Verify column count matches placeholder count**

  Count the `?` in each statement and the values in each tuple — both must equal 18. A mismatch causes a runtime crash.

- [ ] **Step 4: Commit**

  ```bash
  git add app/core/db.py
  git commit -m "feat(db): persist image_source and user_image_status in both sync paths"
  ```

---

## Task 4: Python — `NotificationRequest`, Engine Handlers, SSE Payload

**Files:**
- Modify: `app/core/access_types.py` (lines 22–43)
- Modify: `app/core/ultra_engine.py` (lines 330–395, 401–470, 588–642)
- Modify: `app/core/realtime_agent.py` (lines 380–402)

- [ ] **Step 1: Add two fields to `NotificationRequest`**

  In `app/core/access_types.py`, inside the `NotificationRequest` dataclass after `user_birthday`:

  ```python
  user_birthday: str = ""
  image_source: str = ""      # e.g. "PROFILE_BORROWED", "GYM_UPLOAD", etc.
  user_image_status: str = "" # e.g. "REQUIRED_CHANGE", "OK"
  ```

- [ ] **Step 2: Extract the two values in `_handle_allow`**

  In `ultra_engine.py`, inside `_handle_allow` (line ~330), after the block that reads `user_valid_to`:

  ```python
  user_valid_to   = str(user.get("validTo",  user.get("valid_to",  "")) or "")
  image_source      = str(user.get("imageSource",     "") or "")
  user_image_status = str(user.get("userImageStatus", "") or "")
  ```

  Then pass them to the `_enqueue_notification` call at the bottom of `_handle_allow`:

  ```python
  self._enqueue_notification(
      ...
      image_source=image_source,
      user_image_status=user_image_status,
  )
  ```

- [ ] **Step 3: Extract the two values in `_handle_totp_rescue`**

  In `_handle_totp_rescue` (line ~401), the `user` dict comes from `result.get("user")` where `result` is the return value of `verify_totp()`. `verify_totp` receives the already-coerced `users_by_am` / `users_by_card` dicts, so the returned `user` is already camelCase. Use the same pattern:

  ```python
  user_valid_to   = str(user.get("validTo",  user.get("valid_to",  "")) or "")
  image_source      = str(user.get("imageSource",     "") or "")
  user_image_status = str(user.get("userImageStatus", "") or "")
  ```

  Then pass them to `_enqueue_notification` in the `_handle_totp_rescue` call site.

- [ ] **Step 4: Update `_enqueue_notification` signature and body**

  Add two keyword-only parameters with defaults, and forward them to `NotificationRequest`:

  ```python
  def _enqueue_notification(
      self,
      *,
      event_id: str,
      allowed: bool,
      reason: str,
      scan_mode: str,
      user_full_name: str,
      user_image: str,
      user_membership_id: Optional[int],
      user_phone: str,
      user_valid_from: str,
      user_valid_to: str,
      image_source: str = "",
      user_image_status: str = "",
  ):
      ...
      req = NotificationRequest(
          ...
          image_source=image_source,
          user_image_status=user_image_status,
      )
  ```

- [ ] **Step 5: Add two fields to `_popup_payload_from_request`**

  In `app/core/realtime_agent.py`, inside `_popup_payload_from_request` (line ~380), add after `"userBirthday"`:

  ```python
  "userBirthday":    req.user_birthday,
  "imageSource":     req.image_source,
  "userImageStatus": req.user_image_status,
  ```

- [ ] **Step 6: Smoke-test imports**

  ```bash
  cd /c/Users/mohaa/Desktop/monclub_access_python
  python -c "from app.core.ultra_engine import UltraEngine; from app.core.realtime_agent import RealtimeAgent; print('OK')"
  ```
  Expected: `OK`

- [ ] **Step 7: Commit**

  ```bash
  git add app/core/access_types.py app/core/ultra_engine.py app/core/realtime_agent.py
  git commit -m "feat(engine): thread imageSource and userImageStatus through engine to SSE payload"
  ```

---

## Task 5: Tauri UI — Types + Popup Components

**Files:**
- Modify: `tauri-ui/src/api/types.ts` (lines 886–910)
- Modify: `tauri-ui/src/pages/PopupWindow.tsx`
- Modify: `tauri-ui/src/components/NotificationPopup.tsx`

- [ ] **Step 1: Add two optional fields to `PopupEvent`**

  In `tauri-ui/src/api/types.ts`, inside the `PopupEvent` interface after `userBirthday`:

  ```typescript
  /** ISO date string of the member's birthday, if available */
  userBirthday?: string;
  /** "PROFILE_BORROWED" | "GYM_UPLOAD" | "GYM_CAPTURE" | "GYM_GALLERY" | undefined */
  imageSource?: string;
  /** "REQUIRED_CHANGE" | "OK" | undefined */
  userImageStatus?: string;
  ```

  Fields are optional for backward compatibility with old sync data and old backend responses.

- [ ] **Step 2: Add mappings in `toPopupEvent()` in `PopupWindow.tsx`**

  In `tauri-ui/src/pages/PopupWindow.tsx`, inside `toPopupEvent()` (line ~14–44), after the `userBirthday` mapping:

  ```typescript
  userBirthday: raw?.userBirthday ? String(raw.userBirthday) : undefined,
  imageSource:     raw?.imageSource     ? String(raw.imageSource)     : undefined,
  userImageStatus: raw?.userImageStatus ? String(raw.userImageStatus) : undefined,
  ```

- [ ] **Step 3: Add image flag badges to `PopupWindow.tsx` layout**

  `PopupWindow.tsx` uses Tailwind CSS — do NOT use MUI Chip here. Insert a new block in the right panel **after the membership ID pill** (after line 392, before the divider at line 394):

  ```tsx
  {/* image flags */}
  {(n.imageSource === 'PROFILE_BORROWED' || n.userImageStatus === 'REQUIRED_CHANGE') && (
    <div className="flex flex-wrap gap-2 mb-4">
      {n.imageSource === 'PROFILE_BORROWED' && (
        <span
          className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium"
          style={{ background: 'rgba(255,255,255,0.08)', color: '#a1a1aa' }}
        >
          👤 Profile photo — no gym image set
        </span>
      )}
      {n.userImageStatus === 'REQUIRED_CHANGE' && (
        <span
          className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium"
          style={{ background: 'rgba(251,146,60,0.15)', color: '#fb923c', border: '1px solid rgba(251,146,60,0.3)' }}
        >
          ⚠ Image change required
        </span>
      )}
    </div>
  )}
  ```

- [ ] **Step 4: Add MUI Chips to `NotificationPopup.tsx`**

  `NotificationPopup.tsx` uses MUI. Add the two chips **directly after the image/placeholder `Box`** (after line 79). `Chip` and `PersonIcon` are already imported — only add the one missing import:

  ```typescript
  import WarningAmberIcon from '@mui/icons-material/WarningAmber';
  ```

  Then in the JSX, after the image box closes:

  ```tsx
  {popup.imageSource === 'PROFILE_BORROWED' && (
    <Chip
      size="small"
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

- [ ] **Step 5: Build check**

  ```bash
  cd /c/Users/mohaa/Desktop/monclub_access_python/tauri-ui
  npm run build 2>&1 | tail -20
  ```
  Expected: no TypeScript errors, build succeeds.

- [ ] **Step 6: Commit**

  ```bash
  git add tauri-ui/src/api/types.ts \
          tauri-ui/src/pages/PopupWindow.tsx \
          tauri-ui/src/components/NotificationPopup.tsx
  git commit -m "feat(ui): show imageSource and userImageStatus flags in door popup"
  ```

---

## End-to-End Verification

After all tasks are done:

1. **Deploy backend** and trigger a full sync from the Python app
2. In the SQLite DB, verify:
   ```sql
   SELECT user_id, image_source, user_image_status FROM sync_users LIMIT 5;
   ```
   — columns exist and have values (or NULL for members with no flag)
3. Scan a card whose member has `imageSource = PROFILE_BORROWED` → popup should show the grey badge
4. Scan a card whose member has `userImageStatus = REQUIRED_CHANGE` → popup should show the orange badge
5. Scan a normal card → no badges shown

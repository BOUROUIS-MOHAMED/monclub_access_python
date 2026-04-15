# Anti-Fraud Daily Pass Limit + Door History Rebuild — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a per-device daily-pass alert (alert-only, never blocks) with sound + popup, add a sound to the existing duration block, fix the dashboard door-history user-info display, and add a per-user entry-summary popup with day/range/per-membership windows.

**Architecture:** Single feature spanning three repos. The daily counter is **computed from `access_history` on every event** (no new state, no reset job). The existing `_FEEDBACK_SOUND_SPECS` machinery is extended with two new kinds. The backend adds one device column and enriches / extends two REST endpoints. The dashboard adds two columns and a modal. Spec reference: `docs/superpowers/specs/2026-04-15-anti-fraud-daily-limit-and-door-history-design.md`.

**Tech Stack:** Spring Boot (Java) backend · Python 3.x access app · React + TypeScript dashboard · SQLite (access app) · PostgreSQL / MySQL (backend — whichever is in use) · Tauri desktop shell · pytest · JUnit · Vitest/Jest.

**Three phases, in order:**
- **Phase 1 — Backend** (`monclub_backend`) — must deploy first so the access-app sync receives the new field
- **Phase 2 — Access App** (`monclub_access_python`) — consumes the new field, emits alerts, writes `access_history`
- **Phase 3 — Dashboard** (`mon_club_dashboard`) — renders enriched door history + new popup

Each phase is independently testable. Phase N+1 can be fully mocked against Phase N's contract.

**Deployment ordering constraint:** Phase 3 (dashboard) must NOT be deployed to production until Phase 1 (backend) is live — the new columns and endpoint it depends on will 404 / return nulls otherwise, breaking the fixed User column display. Phase 2 depends on Phase 1's new field but degrades gracefully to the pre-feature behaviour if the backend hasn't deployed yet (the new field defaults to `0` = disabled).

---

## Phase 1 — Backend (Spring Boot / Java)

> **File paths in this phase are best-effort based on conventional Spring Boot project layout.** The executing engineer MUST confirm the exact paths at the start of each task (`find src/main/java -name "GymDevice.java"` etc.) before editing.

### Task 1.1: Database migration — new column + composite index

**Files:**
- Create: `src/main/resources/db/migration/V<next>__anti_fraude_daily_pass_limit.sql`

- [ ] **Step 1.1.1:** Determine the next Flyway version number by listing `src/main/resources/db/migration/` and picking the next integer.

- [ ] **Step 1.1.2:** Write the migration file.

```sql
-- V<N>__anti_fraude_daily_pass_limit.sql
ALTER TABLE gym_device
    ADD COLUMN anti_fraude_daily_pass_limit INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS ix_access_history_user_door_day
    ON access_history (user_id, device_id, door_number, allowed, created_at);
```

- [ ] **Step 1.1.3:** Run `./mvnw flyway:migrate` (or Gradle equivalent) against the dev database. Expected: migration applies cleanly, no errors.

- [ ] **Step 1.1.4:** Commit.

```bash
git add src/main/resources/db/migration/V<N>__anti_fraude_daily_pass_limit.sql
git commit -m "feat(db): add anti_fraude_daily_pass_limit column and access_history composite index"
```

---

### Task 1.2: `GymDevice` entity — new field

**Files:**
- Modify: `src/main/java/.../model/GymDevice.java`

- [ ] **Step 1.2.1:** Locate the entity and add the field next to the existing `antiFraudeDuration` field.

```java
@Column(name = "anti_fraude_daily_pass_limit", nullable = false)
private int antiFraudeDailyPassLimit = 0;
```

- [ ] **Step 1.2.2:** Regenerate/update getters and setters if the project uses Lombok `@Data`, Lombok takes care of it.

- [ ] **Step 1.2.3:** Compile: `./mvnw compile`. Expected: BUILD SUCCESS.

- [ ] **Step 1.2.4:** Commit.

```bash
git commit -am "feat(model): add antiFraudeDailyPassLimit to GymDevice"
```

---

### Task 1.3: `GymDeviceDto` — expose the new field

**Files:**
- Modify: `src/main/java/.../dto/GymDeviceDto.java`
- Modify: any `GymDeviceMapper` / `toDto` / `fromDto` helper that maps between entity and DTO

- [ ] **Step 1.3.1:** Add `private int antiFraudeDailyPassLimit = 0;` to the DTO with getter/setter.

- [ ] **Step 1.3.2:** Update the mapper (if present) to copy the field both directions.

- [ ] **Step 1.3.3:** Confirm the DTO is the one returned by the `get_gym_users` (device sync) endpoint and by `updateGymDevice`.

- [ ] **Step 1.3.4:** Compile.

- [ ] **Step 1.3.5:** Commit.

```bash
git commit -am "feat(dto): expose antiFraudeDailyPassLimit on GymDeviceDto"
```

---

### Task 1.4: Update endpoint test — round-trip the new field

**Files:**
- Modify: existing `GymDeviceControllerTest.java` (or equivalent)

- [ ] **Step 1.4.1:** Write the failing test for round-tripping the field via `updateGymDevice`.

```java
@Test
void updateGymDevice_persistsAntiFraudeDailyPassLimit() {
    GymDeviceDto dto = /* fetch existing device */;
    dto.setAntiFraudeDailyPassLimit(7);
    mockMvc.perform(patch("/api/v1/devices/" + dto.getId())
            .contentType(APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(dto)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.antiFraudeDailyPassLimit").value(7));
}
```

- [ ] **Step 1.4.2:** Run: `./mvnw test -Dtest=GymDeviceControllerTest`. Expected: FAIL (likely because the field is ignored by the serializer).

- [ ] **Step 1.4.3:** Fix any serialization / validation issue that surfaces. Common cause: missing `@JsonProperty` or a `BeanUtils.copyProperties` call that excludes unknown fields — check the device-update service method.

- [ ] **Step 1.4.4:** Re-run test. Expected: PASS.

- [ ] **Step 1.4.5:** Commit.

```bash
git commit -am "test(device): verify antiFraudeDailyPassLimit round-trips"
```

---

### Task 1.5: Door history endpoint — fix user info

**Files:**
- Modify: `src/main/java/.../controller/AccessHistoryController.java` (or `DoorHistoryController`)
- Modify: `src/main/java/.../service/AccessHistoryService.java`
- Modify: `src/main/java/.../dto/AccessHistoryDto.java` (or `DoorHistoryRowDto`)
- Modify: the repository / JPA query (`AccessHistoryRepository.java`)

- [ ] **Step 1.5.1:** Locate the actual controller class that handles door history — the spec refers to it as both `AccessHistoryController` and `DoorHistoryController`; use the real name found in the repo. `grep -r "by-door\|access-history" src/main/java` then note the controller + service + repository filenames. Use those names consistently in all remaining steps of Tasks 1.5, 1.6. Also read the existing endpoint, DTO, and query — identify why `userId`, `userFullName`, `userImage` are null today. Most likely the JPA projection omits a `LEFT JOIN gym_user` or the DTO mapper silently drops them.

- [ ] **Step 1.5.2:** Write the failing test.

```java
@Test
void getDoorHistory_includesUserInfo() {
    mockMvc.perform(get("/api/v1/access-history/by-door")
            .param("deviceId", "1").param("doorNumber", "1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.content[0].userFullName").isNotEmpty())
        .andExpect(jsonPath("$.content[0].userImage").exists())
        .andExpect(jsonPath("$.content[0].userActiveMembershipName").exists());
}
```

- [ ] **Step 1.5.3:** Run: FAIL.

- [ ] **Step 1.5.4:** Add the fields to the DTO.

```java
private Long userId;
private String userFullName;
private String userImage;
private String userActiveMembershipName;
```

- [ ] **Step 1.5.5:** Update the query. If the repo uses a JPQL projection, change it to:

```java
@Query("""
    SELECT new com....DoorHistoryRowDto(
        ah.id, ah.createdAt, ah.deviceId, d.name, ah.doorNumber,
        u.id, u.fullName, u.image,
        am.name,
        ah.allowed, ah.reason, ah.scanMode
    )
    FROM AccessHistory ah
    LEFT JOIN GymDevice d ON d.id = ah.deviceId
    LEFT JOIN GymUser u   ON u.id = ah.userId
    LEFT JOIN ActiveMembership am ON am.userId = u.id AND am.active = true
    WHERE ah.deviceId = :deviceId AND ah.doorNumber = :doorNumber
    ORDER BY ah.createdAt DESC
    """)
Page<DoorHistoryRowDto> findByDoor(...);
```

- [ ] **Step 1.5.6:** Run test. Expected: PASS.

- [ ] **Step 1.5.7:** Commit.

```bash
git commit -am "fix(access-history): include user info in door history rows"
```

---

### Task 1.6: Door history endpoint — violationType + dailyStatus

**Files:**
- Modify: same as Task 1.5

- [ ] **Step 1.6.1:** Add the new fields to the DTO.

```java
private String violationType;       // null | "DURATION" | "DAILY_LIMIT"
private Integer userCountThatDay;   // inclusive of current row
private Integer dailyLimitForDoor;
```

- [ ] **Step 1.6.2:** Write the failing test.

```java
@Test
void getDoorHistory_tagsDailyLimitRowsWhenLimitIsSet() {
    // arrange: device with antiFraudeDailyPassLimit=2, insert 3 allowed entries today
    // ...
    mockMvc.perform(get("/api/v1/access-history/by-door").param(...))
        .andExpect(jsonPath("$.content[0].violationType").value("DAILY_LIMIT"))
        .andExpect(jsonPath("$.content[0].userCountThatDay").value(3))
        .andExpect(jsonPath("$.content[0].dailyLimitForDoor").value(2));
}

@Test
void getDoorHistory_tagsDurationDenials() {
    // arrange: insert a DENY_ANTI_FRAUD_CARD row
    mockMvc.perform(get("/api/v1/access-history/by-door").param(...))
        .andExpect(jsonPath("$.content[0].violationType").value("DURATION"));
}
```

- [ ] **Step 1.6.3:** Run: FAIL.

- [ ] **Step 1.6.4:** Extend the query with a correlated subquery for `userCountThatDay` (the same-day allowed count for that (user, device, door)) and a join to `gym_device.anti_fraude_daily_pass_limit`.

```sql
-- inside the JPQL projection:
(SELECT COUNT(ah2) FROM AccessHistory ah2
  WHERE ah2.userId     = ah.userId
    AND ah2.deviceId   = ah.deviceId
    AND ah2.doorNumber = ah.doorNumber
    AND ah2.allowed    = true
    AND DATE(ah2.createdAt) = DATE(ah.createdAt)
) AS userCountThatDay,
d.antiFraudeDailyPassLimit AS dailyLimitForDoor
```

**Timezone alignment check:** `DATE(createdAt)` above must use the same local-TZ semantic as the access app's `date('now', 'localtime')` in Task 2.3. If the backend DB stores timestamps in UTC, replace `DATE(ah2.createdAt)` with the dialect-appropriate "local-calendar-day" expression (PostgreSQL: `DATE(ah2.createdAt AT TIME ZONE 'Africa/Algiers')`, MySQL: `DATE(CONVERT_TZ(ah2.createdAt,'+00:00','+01:00'))`, or equivalent). A mismatch here causes a day of off-by-one drift every midnight, where the dashboard and the access PC disagree about which day a scan belongs to. Before merging, the implementer must verify that inserting a row at 00:30 local time is counted as "today" by BOTH systems.

- [ ] **Step 1.6.5:** In the service layer (post-query), derive `violationType`:

```java
private String computeViolationType(AccessHistoryRow row) {
    if ("DENY_ANTI_FRAUD_CARD".equals(row.reason) ||
        "DENY_ANTI_FRAUD_QR".equals(row.reason)) return "DURATION";
    if (row.allowed && row.dailyLimitForDoor > 0
        && row.userCountThatDay > row.dailyLimitForDoor) return "DAILY_LIMIT";
    return null;
}
```

- [ ] **Step 1.6.6:** Run tests. Expected: PASS.

- [ ] **Step 1.6.7:** Commit.

```bash
git commit -am "feat(access-history): add violationType and daily-status fields to door history rows"
```

---

### Task 1.7: User entry summary endpoint — skeleton + `byDay`

**Files:**
- Create: `src/main/java/.../controller/UserEntrySummaryController.java`
- Create: `src/main/java/.../service/UserEntrySummaryService.java`
- Create: `src/main/java/.../dto/UserEntrySummaryDto.java` (+ inner classes / records)

- [ ] **Step 1.7.1:** Create the DTO hierarchy — records are cleanest.

```java
public record UserEntrySummaryDto(
    UserHeader user,
    WindowSummary byDay,
    WindowSummary byRange,
    List<MembershipWindowSummary> byMembership,
    List<DailyBucket> daily30,
    List<RecentRow> recent
) {
    public record UserHeader(Long id, String fullName, String image,
                             String phone, String email) {}
    public record WindowSummary(String from, String to,
                                int totalEntries, int totalDenied,
                                List<PerDoor> perDoor) {}
    public record MembershipWindowSummary(Long membershipId, String membershipName,
                                          String startDate, String endDate,
                                          int totalEntries, int totalDenied,
                                          List<PerDoor> perDoor) {}
    public record PerDoor(Long deviceId, String deviceName, int doorNumber,
                          int entries, int denied) {}
    public record DailyBucket(String date, int entries, int denied) {}
    public record RecentRow(Long id, String timestamp, String deviceName,
                            int doorNumber, boolean allowed, String reason,
                            String scanMode) {}
}
```

- [ ] **Step 1.7.2:** Create the controller.

```java
@RestController
@RequestMapping("/api/v1/access-history")
public class UserEntrySummaryController {
    private final UserEntrySummaryService service;

    @GetMapping("/user-summary/{userId}")
    public UserEntrySummaryDto getSummary(
        @PathVariable Long userId,
        @RequestParam(required = false) LocalDate dayDate,
        @RequestParam(required = false) LocalDate rangeFrom,
        @RequestParam(required = false) LocalDate rangeTo,
        @RequestParam(defaultValue = "20") int recentLimit
    ) {
        return service.build(userId, dayDate, rangeFrom, rangeTo,
                             Math.min(recentLimit, 100));
    }
}
```

- [ ] **Step 1.7.3:** Implement the service with just `user` + `byDay` for now — other windows come in later tasks.

- [ ] **Step 1.7.4:** Write the failing test.

```java
@Test
void userSummary_byDay_countsEntriesPerDoor() {
    // arrange: 3 allowed + 1 denied entry today for user 42 on device 1 / door 1
    mockMvc.perform(get("/api/v1/access-history/user-summary/42")
            .param("dayDate", LocalDate.now().toString()))
        .andExpect(jsonPath("$.byDay.totalEntries").value(3))
        .andExpect(jsonPath("$.byDay.totalDenied").value(1))
        .andExpect(jsonPath("$.byDay.perDoor[0].entries").value(3));
}
```

- [ ] **Step 1.7.5:** Run → FAIL → implement → PASS.

- [ ] **Step 1.7.6:** Commit.

```bash
git commit -am "feat(summary): add user entry summary endpoint skeleton with byDay window"
```

---

### Task 1.8: User entry summary — `byRange` + `daily30`

- [ ] **Step 1.8.1:** Write failing tests for both windows.

```java
@Test
void userSummary_byRange_sumsAcrossDays() { ... }

@Test
void userSummary_daily30_isAlwaysExactly30Items() {
    mockMvc.perform(get("/api/v1/access-history/user-summary/42"))
        .andExpect(jsonPath("$.daily30.length()").value(30));
}
```

- [ ] **Step 1.8.2:** Implement `byRange` (same shape as `byDay` with explicit from/to).

- [ ] **Step 1.8.3:** Implement `daily30`:
  - Query `GROUP BY DATE(created_at)` for the last 30 days
  - Zero-fill missing days in Java so the list is always exactly 30 items, oldest first

```java
List<DailyBucket> daily30 = buildDaily30(userId); // zero-fills

private List<DailyBucket> buildDaily30(Long userId) {
    Map<LocalDate, int[]> buckets = repo.countsByDate(userId, LocalDate.now().minusDays(29));
    List<DailyBucket> out = new ArrayList<>(30);
    for (int i = 29; i >= 0; i--) {
        LocalDate d = LocalDate.now().minusDays(i);
        int[] c = buckets.getOrDefault(d, new int[]{0, 0});
        out.add(new DailyBucket(d.toString(), c[0], c[1]));
    }
    return out;
}
```

- [ ] **Step 1.8.4:** Run tests → PASS.

- [ ] **Step 1.8.5:** Commit.

```bash
git commit -am "feat(summary): add byRange and daily30 windows"
```

---

### Task 1.9: User entry summary — `byMembership` + `recent`

- [ ] **Step 1.9.1:** Write failing tests.

```java
@Test
void userSummary_byMembership_listsEachActiveMembershipSeparately() {
    // arrange: 2 active memberships for user
    mockMvc.perform(get("/api/v1/access-history/user-summary/42"))
        .andExpect(jsonPath("$.byMembership.length()").value(2));
}

@Test
void userSummary_byMembership_clampsWindowToEndDateWhenPassed() {
    // arrange: active membership with endDate in the past + entries after endDate
    // assert: those entries are NOT counted
}

@Test
void userSummary_recent_respectsLimit() {
    mockMvc.perform(get("/api/v1/access-history/user-summary/42")
            .param("recentLimit", "5"))
        .andExpect(jsonPath("$.recent.length()").value(5));
}
```

- [ ] **Step 1.9.2:** Implement `byMembership`:
  - Query `ActiveMembership` filtered on `active = true` for the user
  - For each, compute the window `[startDate, min(today, endDate)]`
  - Run the same per-door aggregation query for that window

- [ ] **Step 1.9.3:** Implement `recent`:
  - `ORDER BY createdAt DESC LIMIT :recentLimit`

- [ ] **Step 1.9.4:** Run all summary tests → PASS.

- [ ] **Step 1.9.5:** Commit.

```bash
git commit -am "feat(summary): add byMembership (clamped to endDate) and recent list"
```

---

### Task 1.10: Phase 1 smoke test — deploy to staging

- [ ] **Step 1.10.1:** Run the full backend test suite: `./mvnw test`. Expected: all green.

- [ ] **Step 1.10.2:** Deploy to staging.

- [ ] **Step 1.10.3:** Manually verify from staging:
  - `GET /api/v1/devices/<id>` returns `antiFraudeDailyPassLimit` (default `0`)
  - `GET /api/v1/access-history/by-door?deviceId=X&doorNumber=Y` returns rows with `userFullName`, `violationType`, `userCountThatDay`, `dailyLimitForDoor`
  - `GET /api/v1/access-history/user-summary/<uid>` returns the 6-section JSON

- [ ] **Step 1.10.4:** Git tag the deploy: `git tag backend/anti-fraud-daily-v1`.

**End of Phase 1.** Backend is now feature-complete. Phase 2 (access app) can consume it.

---

## Phase 2 — Access App (Python)

> File paths in this phase are **verified against the current repo** (`C:\Users\mohaa\Desktop\monclub_access_python`).

### Task 2.1: Access-app DB migration — new column + composite index

**Files:**
- Modify: `app/core/db.py` — `sync_devices` `CREATE TABLE` (around line where `anti_fraude_duration` is defined) and the `ALTER TABLE` migration block

- [ ] **Step 2.1.1:** Read `app/core/db.py` and locate the `sync_devices` table create statement and the idempotent `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` block that handles live-migration of existing DBs.

- [ ] **Step 2.1.2:** Add to both the `CREATE TABLE` and the live-migration block:

```sql
anti_fraude_daily_pass_limit INTEGER NOT NULL DEFAULT 0
```

- [ ] **Step 2.1.3:** In the same migration block, add the composite index on `access_history`:

```python
cur.execute("""
    CREATE INDEX IF NOT EXISTS ix_access_history_user_door_day
    ON access_history (user_id, device_id, door_number, allowed, created_at)
""")
```

- [ ] **Step 2.1.4:** Write a failing test in `tests/test_db_anti_fraud_columns.py` (file exists already per previous grep) — extend it.

```python
def test_sync_devices_has_anti_fraude_daily_pass_limit_column(tmp_db):
    cols = {row[1] for row in tmp_db.execute(
        "PRAGMA table_info(sync_devices)").fetchall()}
    assert "anti_fraude_daily_pass_limit" in cols

def test_access_history_composite_index_exists(tmp_db):
    rows = tmp_db.execute(
        "SELECT name FROM sqlite_master WHERE type='index' "
        "AND tbl_name='access_history'").fetchall()
    names = {r[0] for r in rows}
    assert "ix_access_history_user_door_day" in names
```

- [ ] **Step 2.1.5:** Run: `pytest tests/test_db_anti_fraud_columns.py -v`. Expected: FAIL.

- [ ] **Step 2.1.6:** Apply the migration edit. Re-run → PASS.

- [ ] **Step 2.1.7:** Commit.

```bash
git add app/core/db.py tests/test_db_anti_fraud_columns.py
git commit -m "feat(db): add anti_fraude_daily_pass_limit column and access_history composite index"
```

---

### Task 2.2: Settings normalization — three layers

**Files:**
- Modify: `app/core/settings_reader.py` — `normalize_device_settings()`
- Modify: `app/core/db.py` — `_coerce_device_row_to_payload()`
- Modify: `app/core/device_sync.py` — `_normalize_device()`
- Modify: `tests/test_settings_anti_fraud.py` (file exists)

- [ ] **Step 2.2.1:** Write failing tests in `tests/test_settings_anti_fraud.py`.

```python
def test_normalize_device_settings_exposes_daily_pass_limit():
    out = normalize_device_settings({"antiFraudeDailyPassLimit": 7})
    assert out["anti_fraude_daily_pass_limit"] == 7

def test_normalize_device_settings_clamps_daily_pass_limit():
    assert normalize_device_settings({"antiFraudeDailyPassLimit": -5})["anti_fraude_daily_pass_limit"] == 0
    assert normalize_device_settings({"antiFraudeDailyPassLimit": 500})["anti_fraude_daily_pass_limit"] == 100

def test_normalize_device_settings_defaults_daily_pass_limit_to_zero():
    assert normalize_device_settings({})["anti_fraude_daily_pass_limit"] == 0

def test_coerce_device_row_preserves_daily_pass_limit():
    row = {"anti_fraude_daily_pass_limit": 12, ...}
    payload = _coerce_device_row_to_payload(row)
    assert payload["antiFraudeDailyPassLimit"] == 12
```

- [ ] **Step 2.2.2:** Run → FAIL.

- [ ] **Step 2.2.3:** Add the three layers.

In `settings_reader.py` `normalize_device_settings`:

```python
"anti_fraude_daily_pass_limit": _clamp_int(
    raw.get("antiFraudeDailyPassLimit"), default=0, lo=0, hi=100
),
```

In `db.py` `_coerce_device_row_to_payload`:

```python
"antiFraudeDailyPassLimit": int(row["anti_fraude_daily_pass_limit"] or 0),
```

In `device_sync.py` `_normalize_device`:

The existing three anti-fraud keys at lines 1084–1087 use a `g()` helper that accepts both snake_case and camelCase lookup keys. **Do not invent a new pattern — read those four lines first and copy the style exactly.** The ADDITION should look like:

```python
"anti_fraude_daily_pass_limit": _to_int(
    g("anti_fraude_daily_pass_limit", "antiFraudeDailyPassLimit", default=0),
    default=0,
) or 0,
```

(Column 1 shown here is illustrative — the real call must match whatever the surrounding three lines actually do. If `g()` takes different args or `_to_int` has a different signature in this file, mirror it instead of the snippet above.)

- [ ] **Step 2.2.4:** Run all 3 normalization tests → PASS.

- [ ] **Step 2.2.5:** Commit.

```bash
git commit -am "feat(settings): normalize antiFraudeDailyPassLimit across 3 plumbing layers"
```

---

### Task 2.3: `count_today_for_user_door()` helper

**Files:**
- Modify: `app/core/db.py` — add the helper near the other access_history helpers
- Create: `tests/test_daily_counter.py`

- [ ] **Step 2.3.1:** Write the failing tests.

```python
def test_count_today_zero_when_no_entries(tmp_db):
    assert count_today_for_user_door(
        user_id=1, device_id=1, door_number=1, conn=tmp_db
    ) == 0

def test_count_today_ignores_denied(tmp_db):
    _insert_access_history(tmp_db, user_id=1, allowed=False, ...)
    assert count_today_for_user_door(user_id=1, device_id=1, door_number=1) == 0

def test_count_today_ignores_yesterday(tmp_db):
    _insert_access_history(tmp_db, user_id=1, allowed=True,
                           created_at=(datetime.now() - timedelta(days=1)))
    assert count_today_for_user_door(user_id=1, device_id=1, door_number=1) == 0

def test_count_today_counts_only_matching_door(tmp_db):
    _insert_access_history(tmp_db, user_id=1, door_number=2, allowed=True)
    assert count_today_for_user_door(user_id=1, device_id=1, door_number=1) == 0

def test_count_today_counts_multiple_allowed_today(tmp_db):
    for _ in range(5):
        _insert_access_history(tmp_db, user_id=1, allowed=True)
    assert count_today_for_user_door(user_id=1, device_id=1, door_number=1) == 5
```

- [ ] **Step 2.3.2:** Run → FAIL.

- [ ] **Step 2.3.3:** Implement in `app/core/db.py`.

```python
def count_today_for_user_door(
    *, user_id: int, device_id: int, door_number: int, conn=None
) -> int:
    """
    Number of successful (allowed=1) access_history rows for this user on
    this device's door since local midnight (today in local timezone).
    """
    sql = """
        SELECT COUNT(*) FROM access_history
        WHERE user_id = ?
          AND device_id = ?
          AND door_number = ?
          AND allowed = 1
          AND date(created_at, 'localtime') = date('now', 'localtime')
    """
    c = conn or _get_conn()
    row = c.execute(sql, (user_id, device_id, door_number)).fetchone()
    return int(row[0]) if row else 0
```

- [ ] **Step 2.3.4:** Run all 5 tests → PASS.

- [ ] **Step 2.3.5:** Commit.

```bash
git commit -am "feat(db): add count_today_for_user_door helper"
```

---

### Task 2.4: Feedback sound specs — extend `_FEEDBACK_SOUND_SPECS`

**Files:**
- Modify: `app/api/local_access_api_v2.py` (around line 1321 per the earlier grep)
- Modify: `tests/test_feedback_api.py` (file exists)

- [ ] **Step 2.4.1:** Write failing tests.

```python
def test_anti_fraud_duration_sound_spec_exists():
    spec = _feedback_sound_spec("anti-fraud-duration")
    assert spec["base_name"] == "anti-fraud-duration-default"
    assert spec["source_field"] == "anti_fraud_duration_sound_source"

def test_anti_fraud_daily_limit_sound_spec_exists():
    spec = _feedback_sound_spec("anti-fraud-daily-limit")
    assert spec["base_name"] == "anti-fraud-daily-limit-default"
```

- [ ] **Step 2.4.2:** Run → FAIL.

- [ ] **Step 2.4.3:** Extend the dict.

```python
_FEEDBACK_SOUND_SPECS: Dict[str, Dict[str, str]] = {
    "device-push":   { ... existing ... },
    "sync-complete": { ... existing ... },
    "anti-fraud-duration": {
        "source_field": "anti_fraud_duration_sound_source",
        "path_field":   "anti_fraud_duration_custom_sound_path",
        "base_name":    "anti-fraud-duration-default",
    },
    "anti-fraud-daily-limit": {
        "source_field": "anti_fraud_daily_limit_sound_source",
        "path_field":   "anti_fraud_daily_limit_custom_sound_path",
        "base_name":    "anti-fraud-daily-limit-default",
    },
}
```

- [ ] **Step 2.4.4:** Run → PASS.

- [ ] **Step 2.4.5:** Commit.

```bash
git commit -am "feat(feedback): add anti-fraud-duration and anti-fraud-daily-limit sound kinds"
```

---

### Task 2.5: Default sound files

**Files:**
- Create: `assets/sounds/anti-fraud-duration-default.mp3`
- Create: `assets/sounds/anti-fraud-daily-limit-default.mp3`

- [ ] **Step 2.5.1:** Locate where the existing default sound files live (`grep -r "sync-complete-success" assets/`). Confirm the exact `assets/sounds/` directory — adjust if it's elsewhere.

- [ ] **Step 2.5.2:** Generate two distinct default tones. Easiest path with zero new dependency: use `ffmpeg` to generate beeps.

```bash
# Short alert — 0.5s two-tone chirp for duration block
ffmpeg -f lavfi -i "sine=frequency=880:duration=0.2,sine=frequency=660:duration=0.3" \
       -ac 1 -ab 64k assets/sounds/anti-fraud-duration-default.mp3

# Slightly longer alert — 0.8s three-tone for daily limit
ffmpeg -f lavfi -i "sine=frequency=988:duration=0.25,sine=frequency=784:duration=0.25,sine=frequency=659:duration=0.3" \
       -ac 1 -ab 64k assets/sounds/anti-fraud-daily-limit-default.mp3
```

- [ ] **Step 2.5.3:** Verify both files are < 2 MB and playable.

- [ ] **Step 2.5.4:** Commit.

```bash
git add assets/sounds/anti-fraud-*.mp3
git commit -m "feat(assets): add default alert tones for anti-fraud sounds"
```

---

### Task 2.6: Local `cfg` — 4 new sound config fields

**Files:**
- Modify: `shared/config.py` (or wherever the local `cfg` dataclass lives — check `app/core/config.py` as a fallback)

- [ ] **Step 2.6.1:** Locate the config dataclass. Look for `push_success_sound_source` — its file is the target.

- [ ] **Step 2.6.2:** Add the 4 new fields next to the existing ones.

```python
anti_fraud_duration_sound_source: str = "default"
anti_fraud_duration_custom_sound_path: str = ""
anti_fraud_daily_limit_sound_source: str = "default"
anti_fraud_daily_limit_custom_sound_path: str = ""
```

- [ ] **Step 2.6.3:** If there is a round-trip (load/save) test for `cfg`, extend it to verify the new fields default to the expected values and round-trip through JSON. Otherwise write a new test.

- [ ] **Step 2.6.4:** Run the config tests → PASS.

- [ ] **Step 2.6.5:** Commit.

```bash
git commit -am "feat(config): add anti-fraud sound source/path fields"
```

---

### Task 2.7: Feedback event kinds — emit helpers

**Files:**
- Modify: `app/core/access_types.py` — if there's a Literal / Enum of feedback event kinds, add the two new ones
- Modify: `app/ui/app.py` — the `_feedback_events` queue accepts new kinds; verify nothing filters unknown kinds

- [ ] **Step 2.7.1:** Search for where feedback event kinds are defined or filtered. `grep -n "device-push\|sync-complete" app/`

- [ ] **Step 2.7.2:** Add `"anti-fraud-duration"` and `"anti-fraud-daily-limit"` to any literal/enum/allowlist found.

- [ ] **Step 2.7.3:** If the feedback emit path has a helper (`emit_feedback_event(kind, payload)`), verify it accepts the new kinds without additional wiring.

- [ ] **Step 2.7.4:** **If no allowlist/enum exists** (the emit path accepts arbitrary string kinds) — this task is a no-op. Do NOT invent an allowlist just to have something to do. Instead add a one-line comment near the existing `device-push` / `sync-complete` call sites listing the two new kinds for discoverability, and commit that small doc change.

- [ ] **Step 2.7.5:** Commit if changes were needed.

```bash
git commit -am "feat(feedback): whitelist new anti-fraud feedback kinds"
```

---

### Task 2.8: DecisionService — audio on existing duration block

**Files:**
- Modify: `app/core/realtime_agent.py` around lines 1223–1224 (the existing `DENY_ANTI_FRAUD_*` notification branch)
- Modify: `tests/test_decision_service_anti_fraud.py`

- [ ] **Step 2.8.1:** Write the failing test.

```python
def test_duration_denial_emits_feedback_event():
    svc = _make_decision_service_with_blocked_card(user_id=42, card_no="X")
    events = _capture_feedback_events(svc)
    svc.handle_event(_event(card_no="X"))  # second swipe inside window
    assert any(e["kind"] == "anti-fraud-duration" for e in events)
    evt = next(e for e in events if e["kind"] == "anti-fraud-duration")
    assert evt["payload"]["user_id"] == 42
    assert "remaining_seconds" in evt["payload"]
```

- [ ] **Step 2.8.2:** Run → FAIL.

- [ ] **Step 2.8.3:** In `realtime_agent.py` where the `DENY_ANTI_FRAUD_CARD` / `DENY_ANTI_FRAUD_QR` notification is raised, add a feedback-event emit call alongside.

```python
if reason in ("DENY_ANTI_FRAUD_CARD", "DENY_ANTI_FRAUD_QR"):
    _af_rem = vr.get("_af_remaining", 0.0) if isinstance(vr, dict) else 0.0
    # ... existing notification ...
    self._feedback_queue.emit("anti-fraud-duration", {
        "user_id": ev.user_id,
        "full_name": ev.full_name,
        "device_id": ev.device_id,
        "device_name": ev.device_name,
        "door_number": ev.door_number,
        "remaining_seconds": _af_rem,
    })
```

(The exact name of `_feedback_queue` / `emit` depends on the existing plumbing — use the same call pattern as `device-push` / `sync-complete`. Search for an existing emit call to copy.)

- [ ] **Step 2.8.4:** Run → PASS.

- [ ] **Step 2.8.5:** Commit.

```bash
git commit -am "feat(decision-service): emit anti-fraud-duration feedback event on block"
```

---

### Task 2.9: DecisionService — daily limit check + alert emission

**Files:**
- Modify: `app/core/realtime_agent.py` (DecisionService main event loop, after `guard.record` call)
- Modify: `tests/test_decision_service_anti_fraud.py`

- [ ] **Step 2.9.1:** Write the failing tests.

```python
def test_daily_limit_zero_skips_check_and_emits_nothing(tmp_db):
    # device has anti_fraude_daily_pass_limit=0
    svc = _make_decision_service(limit=0)
    events = _capture_feedback_events(svc)
    svc.handle_event(_allowed_event(user_id=1))
    assert not any(e["kind"] == "anti-fraud-daily-limit" for e in events)

def test_daily_limit_allows_silently_up_to_limit(tmp_db):
    svc = _make_decision_service(limit=3)
    events = _capture_feedback_events(svc)
    for _ in range(3):
        svc.handle_event(_allowed_event(user_id=1))
    assert not any(e["kind"] == "anti-fraud-daily-limit" for e in events)

def test_daily_limit_emits_alert_on_first_overage(tmp_db):
    svc = _make_decision_service(limit=3)
    events = _capture_feedback_events(svc)
    for _ in range(4):  # 4th is over the limit
        svc.handle_event(_allowed_event(user_id=1))
    alerts = [e for e in events if e["kind"] == "anti-fraud-daily-limit"]
    assert len(alerts) == 1
    assert alerts[0]["payload"]["count_today"] == 4
    assert alerts[0]["payload"]["limit"] == 3

def test_daily_limit_emits_alert_every_scan_after_overage(tmp_db):
    svc = _make_decision_service(limit=3)
    events = _capture_feedback_events(svc)
    for _ in range(6):  # 3 silent + 3 alerts
        svc.handle_event(_allowed_event(user_id=1))
    alerts = [e for e in events if e["kind"] == "anti-fraud-daily-limit"]
    assert len(alerts) == 3

def test_daily_limit_counter_is_per_door(tmp_db):
    svc = _make_decision_service(limit=2)
    events = _capture_feedback_events(svc)
    for _ in range(2):
        svc.handle_event(_allowed_event(user_id=1, door_number=1))
    for _ in range(2):
        svc.handle_event(_allowed_event(user_id=1, door_number=2))
    assert not any(e["kind"] == "anti-fraud-daily-limit" for e in events)

def test_daily_limit_counter_is_per_user(tmp_db):
    svc = _make_decision_service(limit=2)
    events = _capture_feedback_events(svc)
    for _ in range(2):
        svc.handle_event(_allowed_event(user_id=1))
    for _ in range(2):
        svc.handle_event(_allowed_event(user_id=2))
    assert not any(e["kind"] == "anti-fraud-daily-limit" for e in events)

def test_daily_limit_skipped_when_user_id_unresolved(tmp_db):
    svc = _make_decision_service(limit=1)
    events = _capture_feedback_events(svc)
    svc.handle_event(_allowed_event(user_id=None))
    assert not any(e["kind"] == "anti-fraud-daily-limit" for e in events)
```

- [ ] **Step 2.9.2:** Run → FAIL.

- [ ] **Step 2.9.3:** Add the daily-limit check in `realtime_agent.py` after the existing `guard.record(...)` block but before `open door`:

```python
# ── [NEW] Daily-pass-limit alert (alert-only, never blocks) ──
_af_limit = int(settings.get("anti_fraude_daily_pass_limit") or 0)
if (
    allowed
    and _history_claimed > 0
    and _af_limit > 0
    and ev.user_id is not None
):
    count_today = count_today_for_user_door(
        user_id=int(ev.user_id),
        device_id=int(ev.device_id),
        door_number=int(ev.door_number),
    )
    if count_today > _af_limit:
        self._feedback_queue.emit("anti-fraud-daily-limit", {
            "user_id": int(ev.user_id),
            "full_name": ev.full_name,
            "count_today": count_today,
            "limit": _af_limit,
            "device_id": int(ev.device_id),
            "device_name": ev.device_name,
            "door_number": int(ev.door_number),
        })
```

- [ ] **Step 2.9.4:** Run all 7 new tests → PASS. Also re-run the existing anti-fraud tests to ensure no regression: `pytest tests/test_decision_service_anti_fraud.py tests/test_anti_fraud.py -v`.

- [ ] **Step 2.9.5:** Commit.

```bash
git commit -am "feat(decision-service): daily pass limit alert-only enforcement"
```

---

### Task 2.10: Tauri UI — new sound config rows

**Files:**
- Modify: `tauri-ui/src/pages/ConfigPage.tsx` (verified via previous grep)
- Modify: `tauri-ui/src/api/types.ts` — add the 4 new config fields

- [ ] **Step 2.10.1:** Locate the existing "Sound" section in `ConfigPage.tsx`. Search for `push_success_sound_source` or `sync_success_sound_source`.

- [ ] **Step 2.10.2:** Add the two new rows mirroring the layout of the existing two. Each row has:
  - Source toggle: Default / Custom
  - File path input (only when Custom selected)
  - Play-sample button
  - Upload button

- [ ] **Step 2.10.3:** Update `types.ts` config type with the 4 new fields.

- [ ] **Step 2.10.4:** Smoke-test the UI: launch the Tauri app in dev mode, open Config, verify the two new rows render, change each to Custom with a test file, save, reopen — value persists.

- [ ] **Step 2.10.5:** Commit.

```bash
git add tauri-ui/src/pages/ConfigPage.tsx tauri-ui/src/api/types.ts
git commit -m "feat(ui): configurable anti-fraud alert sounds in Config page"
```

---

### Task 2.11: Tauri UI — toast + audio playback for new feedback kinds

**Files:**
- Modify: `tauri-ui/src/components/NotificationPopup.tsx` (or `NotificationDrawer.tsx`)
- Modify: the toast rendering / audio playback code

- [ ] **Step 2.11.1:** Find where the existing `device-push` and `sync-complete` feedback events are rendered. Grep: `"device-push"` in `tauri-ui/src`.

- [ ] **Step 2.11.2:** Extend the switch/dispatch to handle the two new kinds:

```tsx
case "anti-fraud-duration":
  return <ToastAlert
    title="Anti-fraude actif"
    body={`${payload.full_name} — ${Math.ceil(payload.remaining_seconds)}s restant · ${payload.device_name} / Porte ${payload.door_number}`}
    tone="warning"
  />;

case "anti-fraud-daily-limit":
  return <ToastAlert
    title="Limite quotidienne dépassée"
    body={`${payload.full_name} — ${payload.count_today}/${payload.limit} · ${payload.device_name} / Porte ${payload.door_number}`}
    tone="error"
  />;
```

- [ ] **Step 2.11.3:** Verify the audio playback path.

  **First check:** search the Tauri frontend for how `device-push` and `sync-complete` play their sounds. `grep -rn "device-push\|sync-complete\|feedback-sound" tauri-ui/src`. If the existing code already fetches a sound URL per `kind`, the new kinds flow through it automatically — **no changes needed, skip to Step 2.11.4**.

  **Only if the existing path is hard-coded to the two old kinds:** add the two new kinds to the switch/lookup. Concretely:

  ```tsx
  // somewhere in the feedback event handler, next to existing cases
  const soundUrl = `/api/v1/feedback-sound/${kind}`;  // reuse existing endpoint
  new Audio(soundUrl).play().catch(() => {});
  ```

  Do NOT build a new audio subsystem — if this step requires more than ~10 lines of new code, stop and re-read the existing path; almost certainly something is already there.

- [ ] **Step 2.11.4:** Manual smoke test: in dev mode, trigger an `anti-fraud-duration` and an `anti-fraud-daily-limit` event (either by swiping test cards or a debug button), verify both toast + sound fire.

- [ ] **Step 2.11.5:** Commit.

```bash
git commit -am "feat(ui): render anti-fraud toasts and play configured alert sounds"
```

---

### Task 2.12: Phase 2 integration test

- [ ] **Step 2.12.1:** Write a single end-to-end pytest that:
  - Stands up an in-memory SQLite with the migrations applied
  - Inserts a device with `anti_fraude_daily_pass_limit=2`
  - Feeds 3 allowed events for user_id=42 on door 1 through DecisionService
  - Asserts 1 `anti-fraud-daily-limit` feedback event was emitted

File: `tests/test_anti_fraud_daily_limit_integration.py`.

- [ ] **Step 2.12.2:** Run the full access-app suite: `pytest tests/ -v`. Expected: all green, no regressions.

- [ ] **Step 2.12.3:** Commit.

```bash
git commit -am "test: end-to-end anti-fraud daily limit feedback flow"
```

**End of Phase 2.** Access app is feature-complete against the backend contract.

---

## Phase 3 — Dashboard (React / TypeScript)

> File paths in this phase are best-effort based on conventional React project layout. The executing engineer MUST confirm each path against the real `mon_club_dashboard` repo layout at task start.

### Task 3.1: `GymDeviceModel` — new field

**Files:**
- Modify: `src/models/GymDeviceModel.ts` (or `src/types/device.ts` — grep for existing `antiFraudeDuration`)

- [ ] **Step 3.1.1:** Locate the model file.

- [ ] **Step 3.1.2:** Add the new field with default.

```ts
antiFraudeDailyPassLimit: number = 0;
```

Include it in `toJson()` / `fromJson()` serialisation.

- [ ] **Step 3.1.3:** Run type-check: `pnpm tsc --noEmit`. Expected: clean.

- [ ] **Step 3.1.4:** Commit.

```bash
git commit -am "feat(model): add antiFraudeDailyPassLimit to GymDevice"
```

---

### Task 3.2: Device edit form — new input

**Files:**
- Modify: the existing device edit form component (grep for `antiFraudeDuration` input)

- [ ] **Step 3.2.1:** In the existing "Anti-Fraude" section, add below the duration input:

```tsx
<FormField
  label="Limite quotidienne par porte"
  helperText="0 = désactivé · max 100 · alerte sonore quand dépassé"
>
  <NumberInput
    value={device.antiFraudeDailyPassLimit}
    onChange={(v) => setDevice({ ...device, antiFraudeDailyPassLimit: v })}
    min={0}
    max={100}
    step={1}
  />
</FormField>
```

- [ ] **Step 3.2.2:** Manual smoke test: open the form, change the value, save, reload, verify it persists.

- [ ] **Step 3.2.3:** Commit.

```bash
git commit -am "feat(device-form): add daily pass limit input"
```

---

### Task 3.3: `<ViolationBadge>` component

**Files:**
- Create: `src/components/access-history/ViolationBadge.tsx`
- Create: `src/components/access-history/ViolationBadge.test.tsx`

- [ ] **Step 3.3.1:** Write the failing tests.

```tsx
describe("<ViolationBadge>", () => {
  it("renders nothing for type=null", () => {
    const { container } = render(<ViolationBadge type={null} />);
    expect(container).toBeEmptyDOMElement();
  });
  it("renders yellow pill for DURATION", () => {
    render(<ViolationBadge type="DURATION" />);
    expect(screen.getByText(/re-entry/i)).toHaveClass(/warning|yellow/);
  });
  it("renders red pill for DAILY_LIMIT", () => {
    render(<ViolationBadge type="DAILY_LIMIT" />);
    expect(screen.getByText(/daily limit/i)).toHaveClass(/error|red/);
  });
});
```

- [ ] **Step 3.3.2:** Run → FAIL.

- [ ] **Step 3.3.3:** Implement.

```tsx
type Props = { type: "DURATION" | "DAILY_LIMIT" | null };

export function ViolationBadge({ type }: Props) {
  if (!type) return null;
  if (type === "DURATION")
    return <Pill tone="warning">🟡 Re-entry within window</Pill>;
  return <Pill tone="error">🔴 Daily limit exceeded</Pill>;
}
```

- [ ] **Step 3.3.4:** Run → PASS.

- [ ] **Step 3.3.5:** Commit.

```bash
git commit -am "feat(components): add ViolationBadge"
```

---

### Task 3.4: `<UserStatusToday>` component

**Files:**
- Create: `src/components/access-history/UserStatusToday.tsx`
- Create: `src/components/access-history/UserStatusToday.test.tsx`

- [ ] **Step 3.4.1:** Failing tests.

```tsx
it("shows '—' when limit=0", () => {
  render(<UserStatusToday entries={3} limit={0} />);
  expect(screen.getByText("—")).toBeInTheDocument();
});
it("shows '5/5' plain when at limit", () => {
  render(<UserStatusToday entries={5} limit={5} />);
  expect(screen.getByText("5/5")).not.toHaveClass(/error/);
});
it("shows '6/5 ⚠' with error badge when above limit", () => {
  render(<UserStatusToday entries={6} limit={5} />);
  expect(screen.getByText(/6\/5/)).toHaveClass(/error/);
});
```

- [ ] **Step 3.4.2:** Implement.

```tsx
type Props = { entries: number; limit: number };

export function UserStatusToday({ entries, limit }: Props) {
  if (limit === 0) return <span className="text-muted">—</span>;
  const exceeded = entries > limit;
  return (
    <span className={exceeded ? "text-error font-semibold" : ""}>
      {entries}/{limit}{exceeded ? " ⚠" : ""}
    </span>
  );
}
```

- [ ] **Step 3.4.3:** Run → PASS.

- [ ] **Step 3.4.4:** Commit.

```bash
git commit -am "feat(components): add UserStatusToday badge"
```

---

### Task 3.5: Door history table — wire new columns + fix user info

**Files:**
- Modify: the existing door history page / table component (grep for `access-history` or `door-history`)
- Modify: the API hook that fetches the endpoint

- [ ] **Step 3.5.1:** Update the API hook's response type to include:

```ts
type DoorHistoryRow = {
  // existing fields
  userId: number | null;
  userFullName: string | null;
  userImage: string | null;
  userActiveMembershipName: string | null;
  violationType: "DURATION" | "DAILY_LIMIT" | null;
  userCountThatDay: number;
  dailyLimitForDoor: number;
};
```

- [ ] **Step 3.5.2:** Update the existing User column to render `userImage` (avatar) + `userFullName` + `userActiveMembershipName` (subtitle). Remove whatever null-placeholder code was there.

- [ ] **Step 3.5.3:** Add two new columns:

```tsx
<Column header="Violation">
  {(row) => <ViolationBadge type={row.violationType} />}
</Column>
<Column header="Today's Status">
  {(row) => <UserStatusToday
    entries={row.userCountThatDay}
    limit={row.dailyLimitForDoor}
  />}
</Column>
```

- [ ] **Step 3.5.4:** Make the User cell clickable to open the summary dialog (wired in Task 3.7 — for now add the click handler that sets `?userSummary={id}` in the URL).

- [ ] **Step 3.5.5:** Manual smoke test: load the page, verify avatars + names render, verify both badges appear on appropriate rows.

- [ ] **Step 3.5.6:** Commit.

```bash
git commit -am "feat(door-history): fix user info display and add violation/status columns"
```

---

### Task 3.6: User-summary API hook

**Files:**
- Modify: `src/api/hooks.ts`
- Create: `src/api/types/userSummary.ts`

- [ ] **Step 3.6.1:** Define the response type mirroring the spec.

```ts
export type UserEntrySummary = {
  user: { id: number; fullName: string; image: string | null;
          phone: string | null; email: string | null };
  byDay: WindowSummary;
  byRange: WindowSummary;
  byMembership: MembershipWindowSummary[];
  daily30: DailyBucket[];
  recent: RecentRow[];
};
// ... sub-types per spec
```

- [ ] **Step 3.6.2:** Add the hook.

```ts
export function useUserEntrySummary(userId: number | null, params: {
  dayDate?: string; rangeFrom?: string; rangeTo?: string; recentLimit?: number;
}) {
  return useQuery({
    queryKey: ["user-summary", userId, params],
    queryFn: () => api.get(`/api/v1/access-history/user-summary/${userId}`, {
      params,
    }).then((r) => r.data as UserEntrySummary),
    enabled: userId !== null,
  });
}
```

- [ ] **Step 3.6.3:** Commit.

```bash
git commit -am "feat(api): add useUserEntrySummary hook"
```

---

### Task 3.7: `<UserSummaryDialog>` — modal shell + URL param wiring

**Files:**
- Create: `src/components/user-summary/UserSummaryDialog.tsx`
- Create: `src/components/user-summary/UserSummaryDialog.test.tsx`

- [ ] **Step 3.7.1:** Write the failing tests.

```tsx
it("opens when ?userSummary=42 is in URL", () => {
  renderWithRouter(<AppShell />, { url: "/door-history?userSummary=42" });
  expect(screen.getByRole("dialog")).toBeInTheDocument();
});
it("closes and removes URL param on ✕ click", async () => {
  renderWithRouter(<AppShell />, { url: "/door-history?userSummary=42" });
  await userEvent.click(screen.getByLabelText(/close/i));
  expect(window.location.search).not.toContain("userSummary");
});
```

- [ ] **Step 3.7.2:** Implement — a modal that reads `userSummary` from the URL, calls the hook, shows a loading state, then renders three tabs whose bodies use placeholder markup for now.

- [ ] **Step 3.7.3:** Commit.

```bash
git commit -am "feat(user-summary): add dialog shell with URL-param deep-linking"
```

---

### Task 3.8: `<PerDoorBreakdownTable>` — shared subcomponent

**Files:**
- Create: `src/components/user-summary/PerDoorBreakdownTable.tsx`

- [ ] **Step 3.8.1:** Implement a small table taking `PerDoor[]` + totals.

```tsx
type Props = { perDoor: PerDoor[]; totalEntries: number; totalDenied: number };

export function PerDoorBreakdownTable({ perDoor, totalEntries, totalDenied }: Props) {
  return (
    <>
      <Summary>{totalEntries} entrées · {totalDenied} refus</Summary>
      <Table>
        <thead><tr><th>Porte</th><th>Entrées</th><th>Refus</th></tr></thead>
        <tbody>
          {perDoor.map((d) => (
            <tr key={`${d.deviceId}-${d.doorNumber}`}>
              <td>{d.deviceName} / {d.doorNumber}</td>
              <td>{d.entries}</td>
              <td>{d.denied}</td>
            </tr>
          ))}
        </tbody>
      </Table>
    </>
  );
}
```

- [ ] **Step 3.8.2:** Commit.

```bash
git commit -am "feat(user-summary): add PerDoorBreakdownTable subcomponent"
```

---

### Task 3.9: `<UserSummaryDialog>` — wire the three tabs

**Files:**
- Modify: `src/components/user-summary/UserSummaryDialog.tsx`

- [ ] **Step 3.9.1:** Replace tab placeholders with real content:

  **Tab 1 — Aujourd'hui:** single `<DatePicker>` bound to a local `dayDate` state (default today); pass the chosen date to the hook's params; render `<PerDoorBreakdownTable>` with `data.byDay`.

  **Tab 2 — Période:** `<DateRangePicker>` with `from` / `to` state (default last 7 days); render `<PerDoorBreakdownTable>` with `data.byRange`.

  **Tab 3 — Abonnement ▾:** if `data.byMembership.length === 0` show "Aucun abonnement actif". Otherwise render a `<Select>` of memberships (label `{name} — {startDate} → {endDate}`); selected membership's data feeds `<PerDoorBreakdownTable>`.

- [ ] **Step 3.9.2:** Hook behaviour: when tab or date changes, re-run the query with the updated params (React Query handles caching automatically).

- [ ] **Step 3.9.3:** Manual smoke test across all three tabs.

- [ ] **Step 3.9.4:** Commit.

```bash
git commit -am "feat(user-summary): wire three window tabs with date pickers"
```

---

### Task 3.10: `<Daily30BarChart>` — universal section

**Files:**
- Create: `src/components/user-summary/Daily30BarChart.tsx`
- Use the chart library already in the project (check `package.json` for recharts, visx, apexcharts, nivo, etc.). If none, add `recharts` as a dep.

- [ ] **Step 3.10.1:** Implement a minimal bar chart.

```tsx
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

type Props = { data: DailyBucket[] };

export function Daily30BarChart({ data }: Props) {
  return (
    <ResponsiveContainer width="100%" height={120}>
      <BarChart data={data}>
        <XAxis dataKey="date" hide />
        <YAxis hide />
        <Tooltip />
        <Bar dataKey="entries" />
      </BarChart>
    </ResponsiveContainer>
  );
}
```

- [ ] **Step 3.10.2:** Include in `UserSummaryDialog` below the tab content, always visible.

- [ ] **Step 3.10.3:** Commit.

```bash
git commit -am "feat(user-summary): add Daily30BarChart universal section"
```

---

### Task 3.11: `<RecentEntriesList>` — universal section

**Files:**
- Create: `src/components/user-summary/RecentEntriesList.tsx`

- [ ] **Step 3.11.1:** Simple list of recent rows.

```tsx
type Props = { items: RecentRow[] };

export function RecentEntriesList({ items }: Props) {
  return (
    <ul className="divide-y">
      {items.map((r) => (
        <li key={r.id} className="py-1 text-sm">
          <time>{formatTime(r.timestamp)}</time>
          {" · "}
          {r.deviceName} / {r.doorNumber}
          {" · "}
          {r.allowed ? "✓" : `✗ ${r.reason ?? ""}`}
        </li>
      ))}
    </ul>
  );
}
```

- [ ] **Step 3.11.2:** Include in `UserSummaryDialog` below the bar chart.

- [ ] **Step 3.11.3:** Commit.

```bash
git commit -am "feat(user-summary): add RecentEntriesList universal section"
```

---

### Task 3.12: Phase 3 polish + e2e smoke

- [ ] **Step 3.12.1:** Verify the dialog is responsive (does not overflow at 1280 × 720).

- [ ] **Step 3.12.2:** Verify deep-linking: paste `/door-history?userSummary=42` directly in the browser → dialog opens on load.

- [ ] **Step 3.12.3:** Run the full test suite: `pnpm test`. Expected: all green.

- [ ] **Step 3.12.4:** Lint: `pnpm lint`. Expected: clean.

- [ ] **Step 3.12.5:** Commit any polish fixes.

```bash
git commit -am "polish(user-summary): responsive fixes and deep-linking verification"
```

**End of Phase 3.** Feature is complete.

---

## Final Cross-Repo Smoke Test

After all three phases are merged and deployed to staging:

- [ ] **1.** On the dashboard, set `antiFraudeDailyPassLimit = 2` on a test device and save.
- [ ] **2.** Wait for (or trigger) the access-app sync — confirm the value lands in its local `sync_devices` row.
- [ ] **3.** With a test member, swipe the card 4 times on Door 1.
- [ ] **4.** Verify on the access PC: first 2 silent, 3rd and 4th show toast + play alert sound. The door opens every time.
- [ ] **5.** In the dashboard door history, verify:
  - All 4 rows display the member's name + avatar + active membership name (previously null).
  - Rows 3 and 4 show a red `🔴 Daily limit exceeded` badge in the Violation column.
  - "Today's Status" column shows `3/2 ⚠`, `4/2 ⚠` respectively.
- [ ] **6.** Click the member's name → summary dialog opens.
- [ ] **7.** Verify `Aujourd'hui` tab shows 4 entries / 0 denied for Door 1.
- [ ] **8.** Verify the URL now contains `?userSummary={id}`; refresh the page, dialog reopens.
- [ ] **9.** Close the dialog → URL param is removed.

Feature is production-ready.

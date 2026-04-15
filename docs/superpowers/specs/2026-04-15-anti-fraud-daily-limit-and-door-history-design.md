# Anti-Fraud Daily Pass Limit + Door History Enrichment Design

**Date:** 2026-04-15
**Status:** Draft
**Repos affected:** `monclub_access_python`, `mon_club_dashboard`, `monclub_backend`
**Builds on:** `docs/superpowers/specs/2026-04-08-anti-fraud-design.md`

---

## Overview

Three coordinated changes delivered as one feature, all surfaced through the dashboard's door history page:

1. **Anti-fraud daily limit (NEW behaviour).** A configurable per-device limit on
   the number of successful entries a single user may make on a given door per
   day. When exceeded, every subsequent successful entry triggers a sound + popup
   alert on the access PC. **Alert-only — never blocks the door.**
2. **Audio alert on the existing duration block.** The existing
   `DENY_ANTI_FRAUD_CARD` / `DENY_ANTI_FRAUD_QR` denial flow already shows a popup;
   we add a configurable sound to it (mirroring the existing `device-push` and
   `sync-complete` feedback sound mechanism).
3. **Door history page rebuild.** Fix the existing user-info display bug, add two
   new columns (per-row violation type + per-user-today status), and add a
   "click user → entry summary popup" with day / range / per-active-membership
   windows, a 30-day bar chart, and a recent-entries list.

---

## Goals

- Add a fourth per-device anti-fraud setting: `antiFraudeDailyPassLimit` (int,
  `0 = disabled`, max 100). Limit is enforced per `(user_id, door_number,
  local-calendar-day)` tuple.
- Counter is **computed from `access_history`**, never persisted as standalone
  state. No daily-reset job, no in-memory drift on restart.
- When a user's successful-entry count for a door on a day **exceeds** the
  configured limit, every subsequent allowed scan emits an `anti_fraud_daily_limit`
  feedback event (sound + popup). Door still opens.
- Add a sound to the existing duration block (popup already exists). Sound config
  is per-app (default file or operator-supplied custom file), reusing
  `_FEEDBACK_SOUND_SPECS`.
- Fix the door history endpoint to include `userId`, `userFullName`, `userImage`,
  and `userActiveMembershipName` (currently null/missing on the dashboard).
- Add `violationType` and per-row `userCountThatDay` + `dailyLimitForDoor` to the
  door history response so the frontend can render the new columns.
- Add a new endpoint that returns a per-user entry summary with three window
  modes (single date, custom range, per-active-membership) plus a 30-day daily
  series and the most recent N entries.

## Non-Goals

- Cross-device daily counters (per-device only — a user with the same card on
  two physical controllers gets two independent counters).
- Manual staff override at the device when the limit is reached (alert-only
  semantics make override unnecessary).
- Persistent counter state separate from `access_history` — the history table
  is the single source of truth.
- Hardware enforcement of the daily limit on the ZKTeco firmware (no such
  parameter exists for C3 controllers; see `2026-04-08-anti-fraud-design.md`).
- Throttling the alert sound when a user repeatedly scans above the limit.
  Per explicit operator decision: every above-limit scan fires a fresh sound.

---

## New Device Field

One new column added across all three repos:

| Field | Type | Default | Range | Description |
|---|---|---|---|---|
| `antiFraudeDailyPassLimit` | integer | `0` | `0–100` | `0` disables the feature. Positive values cap allowed entries per `(user, door, day)`. |

`0`-as-disabled chosen to mirror the existing `anti_fraude_duration` pattern
(no separate boolean toggle) and to keep the device form minimal. Existing
devices migrate transparently to `0` = no behavioural change.

---

## Architecture

### 1. Backend (`monclub_backend` — Java / Spring Boot)

#### 1a. `GymDevice.java` — new column

```java
@Column(name = "anti_fraude_daily_pass_limit", nullable = false)
private int antiFraudeDailyPassLimit = 0;
```

#### 1b. `GymDeviceDto.java` — new field

camelCase `antiFraudeDailyPassLimit`, mapped on read and write. Included in the
`get_gym_users` device-list response (so the access app receives it during sync).

#### 1c. Database migration

```sql
ALTER TABLE gym_device
    ADD COLUMN anti_fraude_daily_pass_limit INTEGER NOT NULL DEFAULT 0;

-- Composite index for the door-history subquery and the access app's
-- count_today_for_user_door() helper. Both queries filter on the same column set.
CREATE INDEX IF NOT EXISTS ix_access_history_user_door_day
    ON access_history (user_id, device_id, door_number, allowed, created_at);
```

The index must land in the **same migration** as the column add — splitting them
risks a deploy where the column exists but the door-history endpoint is
unindexed under load. The same composite shape is required in the access app's
local SQLite (see §2c).

#### 1d. Door history endpoint — fix + enrich

The existing endpoint that powers the dashboard's door history table currently
returns `null` for user identity fields. Add the following:

| Field | Source |
|---|---|
| `userId`, `userFullName`, `userImage` | LEFT JOIN `gym_user` on `access_history.user_id` |
| `userActiveMembershipName` | LEFT JOIN `active_membership` on the user's currently-active membership (if any) |
| `violationType` | Derived from `reason`: `DENY_ANTI_FRAUD_CARD` or `DENY_ANTI_FRAUD_QR` → `"DURATION"`; allowed entries where the running same-day count exceeds the device's `antiFraudeDailyPassLimit` → `"DAILY_LIMIT"`; otherwise `null`. |
| `userCountThatDay` | Subquery: `COUNT(*)` from `access_history` for `(user_id, device_id, door_number, DATE(created_at))` where `allowed = TRUE`. **Inclusive of the current row** — matches the access-app semantic where `count_today_for_user_door()` runs after `insert_access_history`, so the row that triggered an alert is counted in its own `userCountThatDay`. A row with `userCountThatDay = 6` and `dailyLimitForDoor = 5` was the entry that crossed the threshold or one of its successors. |
| `dailyLimitForDoor` | JOIN `gym_device.anti_fraude_daily_pass_limit` |

The frontend computes `exceeded = userCountThatDay > dailyLimitForDoor` and
renders the `Today's Status` badge accordingly.

Existing pagination and filtering remain unchanged. All new joins target
indexed columns; the subquery is bounded by a composite index on
`(user_id, device_id, door_number, allowed, created_at)`.

#### 1e. New endpoint — user entry summary

`GET /api/v1/access-history/user-summary/{userId}`

Single endpoint returns everything needed by the popup in one round-trip
(operators staring at a popup do not want tab-switch latency).

**Query parameters** (all optional, defaults documented inline):
- `dayDate=YYYY-MM-DD` — date for the "by day" window. Default: today, local TZ.
- `rangeFrom=YYYY-MM-DD` and `rangeTo=YYYY-MM-DD` — inclusive bounds for the
  "by range" window. Default: last 7 days ending today.
- `recentLimit=N` — N for the recent-entries list. Default `20`, max `100`.

**Response shape:**

```json
{
  "user": { "id", "fullName", "image", "phone", "email" },

  "byDay": {
    "date": "2026-04-15",
    "totalEntries": 5,
    "totalDenied": 1,
    "perDoor": [
      { "deviceId": 1, "deviceName": "Entrée principale",
        "doorNumber": 1, "entries": 3, "denied": 1 }
    ]
  },

  "byRange": {
    "from": "2026-04-08", "to": "2026-04-15",
    "totalEntries": 32, "totalDenied": 4,
    "perDoor": [ ... ]
  },

  "byMembership": [
    {
      "membershipId", "membershipName", "startDate", "endDate",
      "totalEntries": 87, "totalDenied": 9,
      "perDoor": [ ... ]
    }
  ],

  "daily30": [
    { "date": "2026-03-17", "entries": 2, "denied": 0 }
  ],

  "recent": [
    { "id", "timestamp", "deviceName", "doorNumber",
      "allowed", "reason", "scanMode" }
  ]
}
```

`byMembership` lists every active membership the user holds, each item scoped
to that membership's `[startDate, min(today, endDate)]` window. "Active" means
the membership's `status` flag is active in the backend data model — the
endpoint filters on that flag, not on date arithmetic, so a membership flagged
active even though its `endDate` has passed (a known data condition in the
backend) is still included. The window upper bound is clamped to `endDate` so
the count reflects only entries that occurred during the membership's
contractual period. If the user has no active membership, the array is empty.

`daily30` is always exactly 30 items, oldest first, suitable for direct binding
to a bar chart (zero-fill missing days as `{ entries: 0, denied: 0 }`).

`recent` is newest first, capped at `recentLimit`.

**Authorization:** identical role gate as the existing door history endpoint.
No new auth surface.

---

### 2. Access App (`monclub_access_python` — Python)

#### 2a. Database — `sync_devices` table (`app/core/db.py`)

Add one column:

```sql
anti_fraude_daily_pass_limit INTEGER NOT NULL DEFAULT 0
```

`save_sync_cache_delta` already upserts every backend device field; map the new
camelCase key `antiFraudeDailyPassLimit` to the new snake_case column.

#### 2b. Settings normalization — three layers (mirror the existing pattern)

`normalize_device_settings()` in `app/core/settings_reader.py`:

```python
"anti_fraude_daily_pass_limit": _clamp_int(
    raw.get("antiFraudeDailyPassLimit"), default=0, lo=0, hi=100
),
```

`_coerce_device_row_to_payload()` in `app/core/db.py`:

```python
"antiFraudeDailyPassLimit": int(row["anti_fraude_daily_pass_limit"] or 0),
```

`_normalize_device()` in `app/core/device_sync.py`:

```python
"anti_fraude_daily_pass_limit": _to_int(
    row.get("anti_fraude_daily_pass_limit"), 0
),
```

These three layers are the same plumbing the existing
`anti_fraude_card`/`anti_fraude_qr_code`/`anti_fraude_duration` fields use —
no new infrastructure required.

#### 2c. Helper — `count_today_for_user_door()` (`app/core/db.py`)

```python
def count_today_for_user_door(
    *, user_id: int, device_id: int, door_number: int
) -> int:
    """
    Number of successful entries (allowed=1) by this user on this device's
    given door since local midnight (current calendar date in local TZ).
    """
```

Implementation: single indexed `SELECT COUNT(*)` on `access_history`. A
composite index on `(user_id, device_id, door_number, allowed, created_at)`
keeps the cost O(log n).

#### 2d. DecisionService integration — `realtime_agent.py`

The new daily check fires **after** the existing duration check and **after**
`insert_access_history` (so the just-inserted entry is included in the count):

```
receive event
→ event_id dedup                                            (existing)
→ if anti_fraude_card → guard.check(card)                   (existing)
→ verify_card() / verify_totp() → vr, scan_mode, user_id    (existing)
→ if QR_TOTP & anti_fraude_qr_code → guard.check(qr)        (existing)
→ _history_claimed = insert_access_history(...)             (existing)
→ if allowed & not blocked & _history_claimed > 0:
      guard.record(...)                                     (existing)
→ ──────────── NEW ─────────────
→ if allowed & _history_claimed > 0 & limit > 0 & user_id:
      count_today = count_today_for_user_door(...)
      if count_today > limit:
          emit_feedback_event("anti_fraud_daily_limit", {
              "user_id": user_id,
              "full_name": full_name,
              "count_today": count_today,
              "limit": limit,
              "device_id": device_id,
              "device_name": device_name,
              "door_number": door_number,
          })
→ open door                                                 (existing)
```

**Guard conditions** (mirror existing AntiFraudGuard defensive pattern):

- `limit > 0` short-circuits when the device has the feature disabled.
- `user_id` required — anonymous/unresolved scans skip the check (cannot be
  counted anyway, and would already have been denied).
- `count_today > limit` (strict greater-than) — the Nth entry is fine; only
  entries **above** N trigger.
- `_history_claimed > 0` ensures the current event was actually written
  (prevents duplicate-event re-alerting on retry).

#### 2e. Audio for the existing duration block

When `DecisionService` constructs the `DENY_ANTI_FRAUD_CARD` /
`DENY_ANTI_FRAUD_QR` denial branch, additionally emit a feedback event:

```python
emit_feedback_event("anti_fraud_duration", {
    "user_id": user_id, "full_name": full_name,
    "device_id": device_id, "device_name": device_name,
    "door_number": door_number,
    "remaining_seconds": _af_remaining,
})
```

The popup notification already exists (`reason` propagates through the
notification service); this adds the audio cue.

#### 2f. Feedback sound specs — extend `_FEEDBACK_SOUND_SPECS`

In `app/api/local_access_api_v2.py`:

```python
_FEEDBACK_SOUND_SPECS = {
    "device-push":          { ... existing ... },
    "sync-complete":        { ... existing ... },
    # NEW
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

Two new default sound files shipped under `assets/sounds/`:
- `anti-fraud-duration-default.mp3` — short alert tone (~0.5 s, distinct from
  sync sound).
- `anti-fraud-daily-limit-default.mp3` — slightly longer tone (~0.8 s).

Both follow the existing extension whitelist (mp3/wav/ogg/m4a) and 2 MB cap.

#### 2g. Local sound config (Tauri app config)

Four new fields on the local `cfg` object (NOT on the backend GymDevice — sound
config is per-app, matching the existing pattern). The exact existing field
names to mirror (verified in `app/api/local_access_api_v2.py` `_FEEDBACK_SOUND_SPECS`):

- Existing `device-push` kind uses `push_success_sound_source` and
  `push_success_custom_sound_path`.
- Existing `sync-complete` kind uses `sync_success_sound_source` and
  `sync_success_custom_sound_path`.

The new fields follow the identical `<base>_sound_source` /
`<base>_custom_sound_path` convention:

- `anti_fraud_duration_sound_source: str` (`"default"` | `"custom"`, default `"default"`)
- `anti_fraud_duration_custom_sound_path: str` (default `""`)
- `anti_fraud_daily_limit_sound_source: str` (default `"default"`)
- `anti_fraud_daily_limit_custom_sound_path: str` (default `""`)

The Tauri config UI gets two new rows in the existing "Sound" section, mirroring
the layout of the existing two configurable sounds.

#### 2h. Feedback event consumption

The Tauri UI long-polls `_feedback_events` (via the existing
`_feedback_events_cond` mechanism in `app/ui/app.py`). The two new event kinds
flow through unchanged — the frontend already knows how to play the sound for
the configured `kind` and render a toast.

The toast for `anti_fraud_daily_limit` displays:

> *Karim Ahmed — Limite quotidienne dépassée (6/5) — Entrée principale / Porte 1*

The toast for `anti_fraud_duration` displays:

> *Karim Ahmed — Anti-fraude actif (28 s restant) — Entrée principale / Porte 1*

---

### 3. Dashboard (`mon_club_dashboard` — React / TypeScript)

#### 3a. Device edit form — one new field

Add `antiFraudeDailyPassLimit` to the existing "Anti-Fraude" section:

```
┌─ Anti-Fraude ──────────────────────────────────────────┐
│  Anti-fraude Carte         [ toggle ]                   │
│  Anti-fraude QR Code       [ toggle ]                   │
│  Durée (secondes)          [ 30 ]                       │
│                                                          │
│  Limite quotidienne par porte  [ 0 ]                    │
│  (0 = désactivé · max 100 · alerte sonore quand dépassé)│
└──────────────────────────────────────────────────────────┘
```

Saved through the existing `updateGymDevice` PATCH — no new endpoint.

#### 3b. Door history table — fix + enrich

Two new columns added to the existing table:

```
| Time | User | Device / Door | Result | Violation | Today's Status |
```

Two new presentational components:

- `<ViolationBadge type={"DURATION"|"DAILY_LIMIT"|null}>` — yellow pill for
  `DURATION`, red pill for `DAILY_LIMIT`, nothing for `null`.
- `<UserStatusToday entries={n} limit={l}>` — `"5/5"` plain when at/below the
  limit; `"6/5 ⚠"` red badge when above; `"—"` when `limit = 0`
  (feature disabled for that door's device).

The fixed user-info fields (`userFullName`, `userImage`,
`userActiveMembershipName`) populate the existing User column, replacing the
current null placeholder.

The user name + avatar in the User column is **clickable** — opens
`<UserSummaryDialog userId={n}>`.

#### 3c. User entry summary dialog

`<UserSummaryDialog userId={n}>` — modal, ~720 × 600 px, scrollable on overflow.

**Layout:**

```
┌─ Karim Ahmed ─────────────────────────────────────── ✕ ┐
│ [📷]  Karim Ahmed                                       │
│       +213 555 xx xx xx · karim@example.com             │
├─────────────────────────────────────────────────────────┤
│  [ Aujourd'hui ] [ Période ] [ Abonnement ▾ ]           │
│                                                          │
│  ┌── window-specific content ─────────────────────┐    │
│  │ <date picker | range picker | membership list> │    │
│  │                                                 │    │
│  │ {totalEntries} entrées · {totalDenied} refus   │    │
│  │                                                 │    │
│  │ <PerDoorBreakdownTable data={...}>             │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  ──── Activité — 30 derniers jours ────                 │
│  <Daily30BarChart data={...}>                           │
│                                                          │
│  ──── 20 dernières entrées ────                         │
│  <RecentEntriesList items={...}>                        │
└──────────────────────────────────────────────────────────┘
```

**Tabs at the top** switch the window for the per-door breakdown only:
- `Aujourd'hui` → single date picker (default = today)
- `Période` → from/to date range picker (default = last 7 days)
- `Abonnement ▾` → dropdown listing each active membership separately;
  selecting one fills the per-door table for that membership's
  `[startDate, today]` window

**Bottom section is always visible** (independent of the active tab) — the
30-day bar chart and recent-entries list are universal context. Avoids the
"I clicked tab X and lost the chart" annoyance.

**Components added:**
- `<UserSummaryDialog userId={n}>` — modal shell + tab state
- `<PerDoorBreakdownTable data={...}>` — shared, reused across all 3 tabs
- `<Daily30BarChart data={...}>` — uses the chart library already present in
  the dashboard (recharts if absent)
- `<RecentEntriesList items={...}>` — simple list

**Open / close mechanics:**
- Open via clickable user name in the door history row.
- Triggered by URL param `?userSummary={userId}` so the modal is
  **deep-linkable & refreshable** (operator can paste the URL to a colleague).
- Close = remove the URL param.

---

## Data Flow Summary

```
Operator edits device in dashboard
  → PATCH /updateGymDevice { antiFraudeDailyPassLimit }
  → Backend writes gym_device column
  → Next sync cycle (get_gym_users) includes new field in devices array
  → Access app: save_sync_cache_delta writes to sync_devices column
  → normalize_device_settings() exposes "anti_fraude_daily_pass_limit"
  → DecisionService reads settings per event, calls count_today_for_user_door()
  → If count_today > limit: emit_feedback_event("anti_fraud_daily_limit", ...)
  → Tauri UI plays configured sound + shows toast
  → access_history insertion continues to flow up to backend via sync
  → Dashboard door history endpoint exposes violationType + userCountThatDay
  → Dashboard renders Violation column + Today's Status column
```

---

## Alert Behaviour Matrix

| # | Trigger | Door action | Popup | Sound | Counts toward daily limit? |
|---|---|---|---|---|---|
| 1 | Re-entry within `anti_fraude_duration` on same door | DENY | Yes (existing) | **Yes (NEW)** | No (denial) |
| 2 | First successful entry above `anti_fraude_daily_pass_limit` | ALLOW | Yes (NEW) | Yes (NEW) | Yes (this entry counts) |
| 3 | Every subsequent successful entry while still above limit | ALLOW | Yes (NEW, fires every scan) | Yes (NEW, fires every scan) | Yes |

**Throttling:** explicitly none. Per operator decision, every above-limit scan
emits a fresh sound and a fresh toast.

---

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Operator alert fatigue from un-throttled re-entry sounds | Documented as an explicit operator decision; configurable sound source per device lets operators choose a quieter file |
| `count_today_for_user_door()` becomes slow as `access_history` grows | Composite index on `(user_id, device_id, door_number, allowed, created_at)` keeps the query bounded; events arrive seconds apart at peak, not milliseconds |
| Daily counter "lost" if access app restarts mid-day | None needed — counter is computed from `access_history` on every event, never cached |
| Backend door-history endpoint slows down under the new joins/subquery | All joins target primary-key / indexed columns; the subquery is bounded by the composite index |
| Multiple active memberships make `byMembership` large | Capped naturally by `active_membership` row count (typically 1–3 per user); each item is small |
| Default sound files clash with existing sync/push sounds in tone | Two new distinct default tones (~0.5 s and ~0.8 s) at different pitches |

---

## Success Criteria

- Setting `antiFraudeDailyPassLimit = 0` in the dashboard disables the feature
  for that device — no counter query runs, no alerts fire. Existing behaviour
  preserved exactly.
- Setting `antiFraudeDailyPassLimit = 5` and having a user (card or QR) make 6
  successful entries on Door 1 results in: 5 silent admits, then 1 admit + sound
  + popup. The user is **not** denied — door opens normally.
- A 7th entry triggers another sound + popup. So does the 8th, etc.
- The same user using Door 2 (different door, same device) retains an
  independent counter — they may still admit silently up to 5 times on Door 2.
- At local midnight, the next entry on Door 1 by that user starts a fresh count
  of 1 — no leftover state.
- The existing `DENY_ANTI_FRAUD_CARD` / `DENY_ANTI_FRAUD_QR` flow now also plays
  the configured `anti-fraud-duration` sound.
- The dashboard door history table renders the user's full name, avatar, and
  active membership name on every row (currently null/missing).
- Each row carries a violation badge when applicable and a `entries/limit`
  badge in the new "Today's Status" column.
- Clicking a user name opens the summary modal, which loads the day, range,
  and per-membership tabs from one API call, plus a 30-day bar chart and a
  list of the user's last 20 entries.
- The modal URL contains `?userSummary={id}` — refreshing the page reopens the
  same modal.

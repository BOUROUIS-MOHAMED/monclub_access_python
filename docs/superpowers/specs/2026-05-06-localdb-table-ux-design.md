# LocalDbPage Table UX Design

**Date:** 2026-05-06  
**Scope:** `tauri-ui/src/pages/LocalDbPage.tsx` — all three tabs (Cache Sync, Access History, Raw Table)  
**Status:** Approved

---

## Problem

The LocalDbPage tables are hard to read:
- Foreign-key columns (`user_id`, `device_id`, `card_no`) show raw IDs with no name resolution or navigation
- Long cell values are silently clipped with no way to view the full content
- Boolean and enum/status columns render as plain `0`/`1` or raw strings instead of colored badges
- Date columns show raw ISO strings
- Column headers are raw `snake_case`

---

## Approach: Smart column builder utility (A)

One new file, one modified file. The existing `DataTable` component is **untouched**.

### New file: `tauri-ui/src/components/ui/smart-columns.tsx`

Exports:
- `buildSmartColumns(keys, rows, context)` → `ColumnDef<any>[]`
- `FkLookupContext` interface
- `CellDetailModal` component

### Modified file: `tauri-ui/src/pages/LocalDbPage.tsx`

- Replace all 3 `useMemo` column builders with calls to `buildSmartColumns`
- Add silent background FK data loading on unlock
- Add one `CellDetailModal` instance at page level

---

## Section 1: FK Lookup Context

When the page unlocks, LocalDbPage silently fetches sync_users and sync_devices in the background. No spinner or button — it is best-effort: if the fetch fails, FK cells degrade gracefully to showing the raw ID.

**FK data loading:**
- Users: `GET /sync/cache/users` → `res.users` — objects are snake_case (field `full_name`, key field `user_id` as number). Build both `userById` (keyed on `user_id`) and `userByCard` (keyed on `first_card_id` and `second_card_id` — insert one entry per non-null card field). No normalisation on card keys.
- Devices: `GET /sync/cache/devices` → `res` — objects are camelCase (field `name`, key field `id` as number). Build `deviceById` keyed on `id`.

```ts
interface FkLookupContext {
  userById: Map<number, { full_name: string; [k: string]: unknown }>;
  userByCard: Map<string, { full_name: string; [k: string]: unknown }>;
  deviceById: Map<number, { name: string; [k: string]: unknown }>;
  onExpand: (title: string, content: React.ReactNode) => void;
}
```

**FK column detection by column name:**

| Column name | Resolves via | Cell display |
|---|---|---|
| `user_id` | `userById` | `Full Name (id)` chip, clickable |
| `card_no`, `cardNo` | `userByCard` | `Full Name` chip, clickable |
| `device_id`, `deviceId` | `deviceById` | `Device Name (id)` chip, clickable |

Clicking a FK chip opens the detail modal in **FK record mode** showing all fields of the related record. The FK record modal skips sensitive/complex fields: `password`, `fingerprints_json`, `face_id`, `qr_code_payload`, `doorPresets`.

Unresolvable FK-like columns (e.g. `membership_id`) fall through to plain text rendering — no crash, no placeholder noise.

---

## Section 2: Cell Type Detection

Each column passes through a detector in priority order. The first match wins.

### Priority order
1. FK column → FK chip renderer
2. Boolean column → boolean badge renderer
3. Enum/status column → color-mapped badge renderer
4. Date column → formatted date renderer
5. Text column → truncate/tooltip/expand renderer

### Boolean columns (detected by name)
`allowed`, `active`, `enabled`, `is_*`, `file_exists`, `completed_fully`, `countable`, `try_to_create`, `created`, `rfid_enabled`, `totp_enabled`, `show_notifications`

→ Green badge for truthy (1 / true / "true"), red badge for falsy (0 / false / "false").

### Enum/status columns (detected by name)
`status`, `state`, `run_type`, `event_type`, `activation_state`, `sync_status`, `manifest_status`, `local_file_state`, `outbox_state`, `result_status`, `player_state`, `render_mode`, `reason`, `operation`, `policy`, `platform`, `access_data_mode`

Color map (case-insensitive substring match):

| Value pattern | Badge color |
|---|---|
| success / ok / active / enabled / allowed / ready / healthy / succeeded / running | green |
| failed / error / blocked / denied / disabled / terminal | red |
| pending / processing / loading / degraded / warning / retryable | amber |
| idle / info / skipped / unknown | slate |
| anything else | secondary (gray) |

### Date columns (detected by name)
Column name ends with `_at`, `At`, `_time`, `Time`, or is `valid_from` / `valid_to`.

→ Formatted using `new Date(v).toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })` — uses the browser/OS locale so output is correct on Windows WebView2. Full ISO value shown as tooltip on hover.

---

## Section 3: Long Value Display

### Truncation tiers

| Value length | Behavior |
|---|---|
| ≤ 60 chars | Show as-is |
| 61–300 chars | Truncate at 60 + `…`, hoverable tooltip shows full text |
| > 300 chars, or valid JSON object/array | Truncate at 60 + `…` + small `⤢` icon button, clicking opens detail modal in **long value mode** |

JSON detection: `JSON.parse(v)` — if result is object or array, modal renders pretty-printed JSON in a `<pre>` block with monospace styling.

The `⤢` expand icon button must have `aria-label="Voir la valeur complète"` and a Radix `<Tooltip>` with the same text for discoverability.

**`TooltipProvider` requirement:** `buildSmartColumns` renders Radix `<Tooltip>` inside table cells. A `<TooltipProvider>` must wrap the `<DataTable>` call in LocalDbPage (one per tab). Add it at the tab content level if it is not already present in a layout ancestor.

**Null / empty values:** Null or empty-string values always render as `—` (muted dash), regardless of column type. Numeric `0` is **not** treated as null — it renders as falsy for boolean columns and as `"0"` for text columns.

**`buildSmartColumns` signature clarification:** `keys` is the definitive column order. If `keys` is empty or absent, fall back to `Object.keys(rows[0])`.

---

## Section 4: The Detail Modal

A single Radix `Dialog` instance lifted to LocalDbPage level. Two modes, one modal.

**Modal state:**
```ts
{ open: boolean; title: string; content: React.ReactNode }
```

Any cell that needs to open it calls `context.onExpand(title, content)`.

### Long value mode
- Title: the column name (humanized)
- Body: full text, or pretty-printed JSON in a scrollable `<pre>` block

### FK record mode
- Title: e.g. `Utilisateur #42` or `Appareil #3`
- Body: two-column key/value grid of all fields on the related record
- Values in the grid are themselves smart-rendered: dates formatted, booleans badged

---

## Section 5: Column Header Humanization

All column headers are converted from `snake_case` / `camelCase` to Title Case.

Special cases:
- `id` → `ID`
- any column ending in `_id` or `Id` → e.g. `user_id` → `User ID`, `deviceId` → `Device ID`
- `card_no` / `cardNo` → `Card No`

---

## Files Summary

| File | Change |
|---|---|
| `tauri-ui/src/components/ui/smart-columns.tsx` | **New** — `buildSmartColumns`, `FkLookupContext`, `CellDetailModal` |
| `tauri-ui/src/pages/LocalDbPage.tsx` | **Modified** — wire FK loading, replace 3 column builders, add modal |

No other files are touched.

---

## Out of scope

- Inline row editing
- Cross-page navigation (clicking a user FK does not navigate to UsersPage)
- Adding new FK relationships beyond user/device/card
- Changes to any page other than LocalDbPage

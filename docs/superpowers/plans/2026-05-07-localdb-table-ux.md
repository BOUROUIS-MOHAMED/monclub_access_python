# LocalDbPage Table UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve the LocalDbPage tables with FK resolution chips, long-value tooltip/modal, status/boolean badges, date formatting, and humanized column headers.

**Architecture:** One new file (`smart-columns.tsx`) exports `buildSmartColumns` and `CellDetailModal`. LocalDbPage replaces its three `useMemo` column builders with calls to `buildSmartColumns`, loads FK lookup data silently on unlock, and renders a single lifted `CellDetailModal`. The existing `DataTable` component is untouched.

**Tech Stack:** React 19, TypeScript, TanStack Table v8, Radix UI (Tooltip, Dialog), Tailwind CSS, Lucide icons

**Spec:** `docs/superpowers/specs/2026-05-06-localdb-table-ux-design.md`

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `tauri-ui/src/components/ui/smart-columns.tsx` | **Create** | All smart column logic: types, detectors, cell renderers, `buildSmartColumns`, `CellDetailModal` |
| `tauri-ui/src/pages/LocalDbPage.tsx` | **Modify** | Wire FK loading, replace 3 column builders, add `<TooltipProvider>`, add `<CellDetailModal>` |

---

## Task 1: Scaffold `smart-columns.tsx` — types and utilities

**Files:**
- Create: `tauri-ui/src/components/ui/smart-columns.tsx`

- [ ] **Step 1: Create the file with the `FkLookupContext` interface and `humanizeKey` utility**

```tsx
// tauri-ui/src/components/ui/smart-columns.tsx
import React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Maximize2 } from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface FkLookupContext {
  userById: Map<number, Record<string, unknown>>;
  userByCard: Map<string, Record<string, unknown>>;
  deviceById: Map<number, Record<string, unknown>>;
  onExpand: (title: string, content: React.ReactNode) => void;
}

export const EMPTY_FK_CONTEXT: FkLookupContext = {
  userById: new Map(),
  userByCard: new Map(),
  deviceById: new Map(),
  onExpand: () => {},
};

// ─── Column header humanization ───────────────────────────────────────────────

export function humanizeKey(key: string): string {
  // special cases first
  if (key === "id") return "ID";
  if (key === "card_no" || key === "cardNo") return "Card No";

  // snake_case → words
  let s = key.replace(/_/g, " ");
  // camelCase → words  (insert space before uppercase letters)
  s = s.replace(/([a-z])([A-Z])/g, "$1 $2");
  // capitalise each word
  s = s.replace(/\b\w/g, (c) => c.toUpperCase());
  // fix " Id" suffix → " ID"
  s = s.replace(/\bId\b/g, "ID");

  return s;
}
```

- [ ] **Step 2: Add column type detectors**

Add these functions to the same file after `humanizeKey`:

```tsx
// ─── Column type detectors ────────────────────────────────────────────────────

const FK_COLS = new Set([
  "user_id", "userId",
  "card_no", "cardNo",
  "device_id", "deviceId",
]);

const BOOL_COLS = new Set([
  "allowed", "active", "enabled", "file_exists", "completed_fully",
  "countable", "try_to_create", "created", "rfid_enabled", "totp_enabled",
  "show_notifications",
]);

const ENUM_COLS = new Set([
  "status", "state", "run_type", "event_type", "activation_state",
  "sync_status", "manifest_status", "local_file_state", "outbox_state",
  "result_status", "player_state", "render_mode", "reason", "operation",
  "policy", "platform", "access_data_mode",
]);

const DATE_SUFFIXES = ["_at", "At", "_time", "Time"];
const DATE_EXACT = new Set(["valid_from", "valid_to", "validFrom", "validTo"]);

export function isFkCol(key: string): boolean {
  return FK_COLS.has(key);
}

export function isBoolCol(key: string): boolean {
  return BOOL_COLS.has(key) || /^is[_A-Z]/.test(key);
}

export function isEnumCol(key: string): boolean {
  return ENUM_COLS.has(key);
}

export function isDateCol(key: string): boolean {
  if (DATE_EXACT.has(key)) return true;
  return DATE_SUFFIXES.some((s) => key.endsWith(s));
}

// ─── Enum badge color mapper ──────────────────────────────────────────────────

const GREEN_PATTERNS = /success|^ok$|active|enabled|allowed|ready|healthy|succeeded|running/i;
const RED_PATTERNS = /failed|error|blocked|denied|disabled|terminal/i;
const AMBER_PATTERNS = /pending|processing|loading|degraded|warning|retryable/i;
const SLATE_PATTERNS = /idle|info|skipped|unknown/i;

export function enumBadgeVariant(
  val: string,
): "success" | "destructive" | "warning" | "secondary" | "outline" {
  if (GREEN_PATTERNS.test(val)) return "success";
  if (RED_PATTERNS.test(val)) return "destructive";
  if (AMBER_PATTERNS.test(val)) return "warning";
  if (SLATE_PATTERNS.test(val)) return "outline";
  return "secondary";
}
```

- [ ] **Step 3: Type-check**

```bash
npx --prefix tauri-ui tsc --noEmit
```

Expected: no errors related to `smart-columns.tsx`.

---

## Task 2: Add cell renderer components

**Files:**
- Modify: `tauri-ui/src/components/ui/smart-columns.tsx`

- [ ] **Step 1: Add `NullDash`, `BoolCell`, `EnumCell`, `DateCell`**

Add after `enumBadgeVariant`:

```tsx
// ─── Null guard ───────────────────────────────────────────────────────────────

/** Returns true when value should render as an em-dash placeholder */
function isNullish(v: unknown): boolean {
  return v === null || v === undefined || v === "";
}

const NullDash = () => (
  <span className="text-muted-foreground select-none">—</span>
);

// ─── Boolean cell ─────────────────────────────────────────────────────────────

export function BoolCell({ value }: { value: unknown }) {
  if (isNullish(value)) return <NullDash />;
  const truthy =
    value === true || value === 1 || value === "true" || value === "1";
  return (
    <Badge
      variant={truthy ? "success" : "destructive"}
      className="text-[10px] font-mono"
    >
      {truthy ? "Oui" : "Non"}
    </Badge>
  );
}

// ─── Enum cell ────────────────────────────────────────────────────────────────

export function EnumCell({ value }: { value: unknown }) {
  if (isNullish(value)) return <NullDash />;
  const s = String(value);
  return (
    <Badge variant={enumBadgeVariant(s)} className="text-[10px] font-mono">
      {s}
    </Badge>
  );
}

// ─── Date cell ────────────────────────────────────────────────────────────────

const DATE_FORMAT_OPTS: Intl.DateTimeFormatOptions = {
  day: "numeric",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
};

export function DateCell({ value }: { value: unknown }) {
  if (isNullish(value)) return <NullDash />;
  const raw = String(value);
  let formatted: string;
  try {
    formatted = new Date(raw).toLocaleString(undefined, DATE_FORMAT_OPTS);
    if (formatted === "Invalid Date") throw new Error();
  } catch {
    return <span className="text-xs">{raw}</span>;
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="text-xs cursor-default tabular-nums">{formatted}</span>
      </TooltipTrigger>
      <TooltipContent>
        <p className="font-mono text-xs">{raw}</p>
      </TooltipContent>
    </Tooltip>
  );
}
```

- [ ] **Step 2: Add `TextCell` (truncation tiers)**

Add after `DateCell`:

```tsx
// ─── Text cell ────────────────────────────────────────────────────────────────

function tryParseJson(s: string): object | null {
  if (s.length < 2) return null;
  const first = s[0];
  if (first !== "{" && first !== "[") return null;
  try {
    const parsed = JSON.parse(s);
    if (typeof parsed === "object" && parsed !== null) return parsed;
    return null;
  } catch {
    return null;
  }
}

export function TextCell({
  value,
  label,
  onExpand,
}: {
  value: unknown;
  label: string;
  onExpand: (title: string, content: React.ReactNode) => void;
}) {
  if (isNullish(value)) return <NullDash />;
  const s = String(value);

  // JSON detection — treat as expandable regardless of length
  const json = tryParseJson(s);
  if (json !== null) {
    const pretty = JSON.stringify(json, null, 2);
    const preview = s.length > 60 ? s.substring(0, 60) + "…" : s;
    return (
      <span className="flex items-center gap-1 text-xs font-mono">
        <span className="text-muted-foreground">{preview}</span>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-4 w-4 shrink-0 opacity-50 hover:opacity-100"
              aria-label="Voir la valeur complète"
              onClick={() =>
                onExpand(
                  label,
                  <pre className="text-xs font-mono whitespace-pre-wrap break-all overflow-auto max-h-[60vh]">
                    {pretty}
                  </pre>,
                )
              }
            >
              <Maximize2 className="h-3 w-3" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Voir la valeur complète</TooltipContent>
        </Tooltip>
      </span>
    );
  }

  // Short — show as-is
  if (s.length <= 60) {
    return <span className="text-xs">{s}</span>;
  }

  const preview = s.substring(0, 60) + "…";

  // Medium (61–300) — truncate + tooltip
  if (s.length <= 300) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="text-xs cursor-default">{preview}</span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs whitespace-pre-wrap break-words">
          {s}
        </TooltipContent>
      </Tooltip>
    );
  }

  // Long (>300) — truncate + expand button
  return (
    <span className="flex items-center gap-1 text-xs">
      <span>{preview}</span>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="h-4 w-4 shrink-0 opacity-50 hover:opacity-100"
            aria-label="Voir la valeur complète"
            onClick={() =>
              onExpand(
                label,
                <p className="text-sm whitespace-pre-wrap break-words">{s}</p>,
              )
            }
          >
            <Maximize2 className="h-3 w-3" />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Voir la valeur complète</TooltipContent>
      </Tooltip>
    </span>
  );
}
```

- [ ] **Step 3: Type-check**

```bash
npx --prefix tauri-ui tsc --noEmit
```

Expected: no new errors.

---

## Task 3: Add `FkChip` and FK record detail content

**Files:**
- Modify: `tauri-ui/src/components/ui/smart-columns.tsx`

- [ ] **Step 1: Add `FkChip` and `FkRecordContent` components**

Add after `TextCell`:

```tsx
// ─── Sensitive field skip list for FK record modal ────────────────────────────

const FK_RECORD_SKIP = new Set([
  "password", "fingerprints_json", "face_id", "qr_code_payload", "doorPresets",
]);

// ─── FK record content (rendered inside modal) ────────────────────────────────

export function FkRecordContent({ record }: { record: Record<string, unknown> }) {
  const entries = Object.entries(record).filter(
    ([k]) => !FK_RECORD_SKIP.has(k),
  );
  return (
    <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
      {entries.map(([k, v]) => (
        <React.Fragment key={k}>
          <span className="text-muted-foreground font-medium whitespace-nowrap">
            {humanizeKey(k)}
          </span>
          <span className="break-all">
            {isNullish(v) ? (
              <span className="text-muted-foreground">—</span>
            ) : isBoolCol(k) ? (
              <BoolCell value={v} />
            ) : isDateCol(k) ? (
              <DateCell value={v} />
            ) : (
              <span className="font-mono text-xs">{String(v)}</span>
            )}
          </span>
        </React.Fragment>
      ))}
    </div>
  );
}

// ─── FK chip cell ─────────────────────────────────────────────────────────────

export function FkChip({
  rawValue,
  resolved,
  record,
  onExpand,
}: {
  rawValue: unknown;
  resolved: string | null;
  record: Record<string, unknown> | null;
  onExpand: FkLookupContext["onExpand"];
}) {
  if (isNullish(rawValue)) return <NullDash />;
  if (!resolved || !record) {
    // Unresolved — show raw value
    return <span className="text-xs font-mono">{String(rawValue)}</span>;
  }
  return (
    <button
      className="inline-flex items-center gap-1 rounded-full bg-primary/8 border border-primary/20 px-2 py-0.5 text-xs font-medium text-primary hover:bg-primary/15 transition-colors cursor-pointer"
      onClick={() =>
        onExpand(resolved, <FkRecordContent record={record} />)
      }
    >
      {resolved}
    </button>
  );
}
```

- [ ] **Step 2: Type-check**

```bash
npx --prefix tauri-ui tsc --noEmit
```

Expected: no new errors.

---

## Task 4: Add `buildSmartColumns` and `CellDetailModal`

**Files:**
- Modify: `tauri-ui/src/components/ui/smart-columns.tsx`

- [ ] **Step 1: Add `buildSmartColumns`**

Add after `FkChip`:

```tsx
// ─── FK resolver helpers ──────────────────────────────────────────────────────

function resolveFk(
  col: string,
  val: unknown,
  ctx: FkLookupContext,
): { label: string; record: Record<string, unknown> } | null {
  if (col === "user_id" || col === "userId") {
    const u = ctx.userById.get(Number(val));
    if (!u) return null;
    const name = (u.fullName ?? u.full_name ?? String(val)) as string;
    return { label: `${name} (#${val})`, record: u };
  }
  if (col === "card_no" || col === "cardNo") {
    const u = ctx.userByCard.get(String(val));
    if (!u) return null;
    const name = (u.fullName ?? u.full_name ?? String(val)) as string;
    return { label: name, record: u };
  }
  if (col === "device_id" || col === "deviceId") {
    const d = ctx.deviceById.get(Number(val));
    if (!d) return null;
    return { label: `${d.name} (#${val})`, record: d };
  }
  return null;
}

// ─── Main builder ─────────────────────────────────────────────────────────────

/**
 * Build smart TanStack column definitions for an arbitrary list of rows.
 *
 * @param keys   Definitive column order. Falls back to Object.keys(rows[0]) if empty/absent.
 * @param rows   Row data (used only for fallback key derivation — not for type inference at runtime).
 * @param ctx    FK lookup maps + expand callback.
 */
export function buildSmartColumns(
  keys: string[] | undefined | null,
  rows: Record<string, unknown>[],
  ctx: FkLookupContext,
): ColumnDef<Record<string, unknown>>[] {
  const cols =
    keys && keys.length > 0
      ? keys
      : rows.length > 0
        ? Object.keys(rows[0])
        : [];

  return cols.map((key): ColumnDef<Record<string, unknown>> => {
    const header = humanizeKey(key);

    return {
      accessorKey: key,
      header,
      cell: ({ row }) => {
        const val = row.original[key];

        // 1. FK
        if (isFkCol(key)) {
          const resolved = isNullish(val) ? null : resolveFk(key, val, ctx);
          return (
            <FkChip
              rawValue={val}
              resolved={resolved?.label ?? null}
              record={resolved?.record ?? null}
              onExpand={ctx.onExpand}
            />
          );
        }

        // 2. Boolean
        if (isBoolCol(key)) return <BoolCell value={val} />;

        // 3. Enum/status
        if (isEnumCol(key)) return <EnumCell value={val} />;

        // 4. Date
        if (isDateCol(key)) return <DateCell value={val} />;

        // 5. Text (with truncation tiers)
        return <TextCell value={val} label={header} onExpand={ctx.onExpand} />;
      },
    };
  });
}
```

- [ ] **Step 2: Add `CellDetailModal`**

Add at the end of the file:

```tsx
// ─── Lifted detail modal ──────────────────────────────────────────────────────

export interface CellDetailModalState {
  open: boolean;
  title: string;
  content: React.ReactNode;
}

export const CLOSED_MODAL: CellDetailModalState = {
  open: false,
  title: "",
  content: null,
};

export function CellDetailModal({
  state,
  onClose,
}: {
  state: CellDetailModalState;
  onClose: () => void;
}) {
  return (
    <Dialog open={state.open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-[600px] max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="text-sm font-semibold">{state.title}</DialogTitle>
        </DialogHeader>
        <div className="overflow-auto flex-1 pt-1 pb-2">{state.content}</div>
      </DialogContent>
    </Dialog>
  );
}
```

- [ ] **Step 3: Type-check**

```bash
npx --prefix tauri-ui tsc --noEmit
```

Expected: no errors in `smart-columns.tsx`.

- [ ] **Step 4: Commit `smart-columns.tsx`**

Run from the project root (`monclub_access_python/`):

```bash
git add tauri-ui/src/components/ui/smart-columns.tsx
git commit -m "feat: add smart-columns utility for LocalDbPage UX"
```

---

## Task 5: Wire FK lookup loading in LocalDbPage

**Files:**
- Modify: `tauri-ui/src/pages/LocalDbPage.tsx`

- [ ] **Step 1: Add imports at the top of LocalDbPage**

Find the existing import block and add:

```tsx
// add to existing imports at top of LocalDbPage.tsx
import {
  buildSmartColumns,
  CellDetailModal,
  FkRecordContent,
  EMPTY_FK_CONTEXT,
  CLOSED_MODAL,
  type FkLookupContext,
  type CellDetailModalState,
} from "@/components/ui/smart-columns";
import { TooltipProvider } from "@/components/ui/tooltip";
```

- [ ] **Step 2: Add FK state and loading inside `LocalDbPage` component**

Find the `// ── data state ──` comment block and add FK state after the existing state declarations (before `const loadSync`):

```tsx
// ── FK lookup context (loaded silently on unlock) ──
const [fkCtx, setFkCtx] = useState<FkLookupContext>(EMPTY_FK_CONTEXT);
const [modalState, setModalState] = useState<CellDetailModalState>(CLOSED_MODAL);

const handleExpand = useCallback((title: string, content: React.ReactNode) => {
  setModalState({ open: true, title, content });
}, []);

const closeModal = useCallback(() => setModalState(CLOSED_MODAL), []);
```

- [ ] **Step 3: Add FK data loading effect**

Add immediately after the FK state block added in Step 2 (before `const loadSync`):

```tsx
// Silently load FK lookup data when the page unlocks
useEffect(() => {
  if (!unlocked) return;
  let cancelled = false;
  (async () => {
    try {
      const [usersRes, devicesRes] = await Promise.all([
        get<any>("/sync/cache/users", { limit: "5000" }),
        get<any>("/sync/cache/devices", { includeDoorPresets: "0" }),
      ]);

      if (cancelled) return;

      const users: any[] = usersRes?.users ?? [];
      const devices: any[] = devicesRes?.devices ?? [];

      const userById = new Map<number, Record<string, unknown>>();
      const userByCard = new Map<string, Record<string, unknown>>();
      users.forEach((u) => {
        const id = u.userId ?? u.user_id;
        if (id != null) userById.set(Number(id), u);
        const c1 = u.firstCardId ?? u.first_card_id;
        const c2 = u.secondCardId ?? u.second_card_id;
        if (c1) userByCard.set(String(c1), u);
        if (c2) userByCard.set(String(c2), u);
      });

      const deviceById = new Map<number, Record<string, unknown>>();
      devices.forEach((d) => {
        if (d.id != null) deviceById.set(Number(d.id), d);
      });

      setFkCtx({ userById, userByCard, deviceById, onExpand: handleExpand });
    } catch {
      // Best-effort — FK chips degrade to raw values silently
    }
  })();
  return () => { cancelled = true; };
}, [unlocked, handleExpand]);
```

- [ ] **Step 4: Type-check**

```bash
npx --prefix tauri-ui tsc --noEmit
```

Expected: no errors.

---

## Task 6: Replace column builders and wire the modal

**Files:**
- Modify: `tauri-ui/src/pages/LocalDbPage.tsx`

- [ ] **Step 1: Replace `syncColumns` builder**

Find and replace the entire `syncColumns` useMemo block:

**Before:**
```tsx
const syncColumns = useMemo<ColumnDef<any, any>[]>(() => {
  if (!syncUsers.length) return [];
  const skipKeys = new Set(["fingerprints_json", "face_id", "qr_code_payload"]);
  return Object.keys(syncUsers[0])
    .filter((k) => !skipKeys.has(k))
    .map((key) => ({
      accessorKey: key,
      header: key.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase()),
      cell: ({ row }: any) => {
        const v = row.original[key];
        if (v == null || v === "") return <span className="text-muted-foreground">—</span>;
        const s = String(v);
        return <span className="text-xs">{s.length > 60 ? s.substring(0, 60) + "…" : s}</span>;
      },
    }));
}, [syncUsers]);
```

**After:**

First, add `SYNC_SKIP` at **module scope** (above the `LocalDbPage` function, not inside it) to avoid re-creation on every render:

```tsx
// Place at module scope, above `export default function LocalDbPage()`:
const SYNC_SKIP = new Set(["fingerprints_json", "face_id", "qr_code_payload"]);
```

Then inside the component, replace the `syncColumns` useMemo:

```tsx
const syncColumns = useMemo(
  () =>
    buildSmartColumns(
      syncUsers.length
        ? Object.keys(syncUsers[0]).filter((k) => !SYNC_SKIP.has(k))
        : [],
      syncUsers,
      { ...fkCtx, onExpand: handleExpand },
    ),
  [syncUsers, fkCtx, handleExpand],
);
```

- [ ] **Step 2: Replace `rawColumns` builder**

**Before:**
```tsx
const rawColumns = useMemo<ColumnDef<any, any>[]>(() => {
  return rawCols.map((col) => ({
    accessorKey: col,
    header: col,
    cell: ({ row }: any) => {
      const v = row.original[col];
      if (v == null || v === "") return <span className="text-muted-foreground">—</span>;
      const s = String(v);
      return <span className="text-xs">{s.length > 80 ? s.substring(0, 80) + "…" : s}</span>;
    },
  }));
}, [rawCols]);
```

**After:**
```tsx
const rawColumns = useMemo(
  () => buildSmartColumns(rawCols, rawRows, { ...fkCtx, onExpand: handleExpand }),
  [rawCols, rawRows, fkCtx, handleExpand],
);
```

- [ ] **Step 3: Replace `historyColumns` builder**

**Before:**
```tsx
const historyColumns = useMemo<ColumnDef<any, any>[]>(() => {
  if (!historyRows.length) return [];
  return Object.keys(historyRows[0]).map((key) => ({
    accessorKey: key,
    header: key.replace(/([A-Z])/g, " $1").replace(/^./, (s: string) => s.toUpperCase()),
    cell: ({ row }: any) => {
      const v = row.original[key];
      if (v == null || v === "") return <span className="text-muted-foreground">—</span>;
      if (key === "allowed")
        return (
          <Badge variant={v ? "success" : "destructive"} className="text-[10px]">
            {v ? "Oui" : "Non"}
          </Badge>
        );
      return <span className="text-xs">{String(v)}</span>;
    },
  }));
}, [historyRows]);
```

**After:**
```tsx
const historyColumns = useMemo(
  () =>
    buildSmartColumns(
      historyRows.length ? Object.keys(historyRows[0]) : [],
      historyRows,
      { ...fkCtx, onExpand: handleExpand },
    ),
  [historyRows, fkCtx, handleExpand],
);
```

- [ ] **Step 4: Add `<CellDetailModal>` and wrap the entire page return with `<TooltipProvider>`**

In the JSX return of `LocalDbPage`, make the following changes:

**a) Wrap the entire page-level `<div className="space-y-4">` with `<TooltipProvider>`.** This ensures all three tabs and the modal body (which also renders `DateCell` tooltips) share the same provider:

```tsx
// Before:
return (
  <div className="space-y-4">
    ...
  </div>
);

// After:
return (
  <TooltipProvider>
    <div className="space-y-4">
      ...
      {/* Cell detail modal — lifted to page level */}
      <CellDetailModal state={modalState} onClose={closeModal} />
    </div>
  </TooltipProvider>
);
```

**b) The three `<DataTable>` calls do NOT need individual `<TooltipProvider>` wrappers** — the single top-level one covers everything including the modal.

- [ ] **Step 5: Remove unused `Badge` import if it's no longer used directly in LocalDbPage**

Check if `Badge` is still used elsewhere in the file (it was used in the old `historyColumns` builder and in the count badges). The count badges like `{syncUsers.length} utilisateurs` still use `<Badge>`, so keep the import.

Also remove any now-unused type imports — the old `ColumnDef` import from `data-table` may be kept since it's still imported by `DataTable`.

- [ ] **Step 6: Final type-check and build**

```bash
npx --prefix tauri-ui tsc --noEmit
```

Expected: zero errors.

- [ ] **Step 7: Commit**

```bash
git add tauri-ui/src/pages/LocalDbPage.tsx
git commit -m "feat: apply smart columns to LocalDbPage — FK chips, badges, date formatting, expand modal"
```

---

## Task 7: Smoke-test visual verification

There is no automated test suite for this UI. Verify manually:

- [ ] **Step 1: Start the dev server**

Run from the project root (`monclub_access_python/`):

```bash
npm --prefix tauri-ui run dev
```

- [ ] **Step 2: Navigate to Local DB page and unlock**

Enter the admin password to unlock the page.

- [ ] **Step 3: Verify Cache Sync tab**
  - Load the sync cache and confirm:
    - Date columns (`valid_from`, `valid_to`) show formatted dates, not raw ISO strings
    - Boolean columns (`active`, `enabled`) show green/red badges
    - `user_id` / `device_id` cells show FK chips with names (if data is loaded)
    - Long cells have `…` truncation; >300-char cells have the expand `⤢` button
    - Clicking a FK chip opens the detail modal with the record's key/value grid

- [ ] **Step 4: Verify Access History tab**
  - Load access history and confirm:
    - `allowed` column renders as green/red badge (`Oui`/`Non`)
    - `card_no` / `cardNo` FK chip shows user name if resolved
    - `device_id` / `deviceId` FK chip shows device name
    - `event_time` / `createdAt` dates are formatted

- [ ] **Step 5: Verify Raw Table tab**
  - Load `sync_users` table and confirm smart column rendering
  - Load `access_history` table and confirm FK chips, badges, dates
  - Load `fingerprints` table and confirm long binary data gets expand button
  - Load `auth_tokens` table and confirm date/status columns work

- [ ] **Step 6: Verify the detail modal**
  - Click an FK chip → modal opens with record fields
  - Sensitive fields (`password`) are not shown
  - Click a long-value expand button → modal shows full text / formatted JSON
  - Closing the modal works (click X or click outside)

---

## Implementation Notes

### Key casing defensive handling
The FK loading effect uses `u.userId ?? u.user_id` to handle both camelCase (from `/sync/cache/users` TypeScript DTO) and snake_case (actual Python API response). Both are handled in `resolveFk` for the same reason.

### `SYNC_SKIP` constant
`SYNC_SKIP` is declared at **module scope** (above `export default function LocalDbPage()`), not inside the component. Task 6 Step 1 places it there explicitly.

### Tooltip portal
Radix Tooltip uses a portal — it renders outside the table DOM, so it won't be clipped by `overflow: hidden` on the table container. No special CSS overrides needed.

### Badge variant "destructive" vs "warning"
`badge.tsx` uses `destructive` (red) for false/failed values. There is no `danger` variant — always use `destructive`.

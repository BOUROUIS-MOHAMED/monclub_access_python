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
    const d = new Date(raw);
    if (Number.isNaN(d.getTime())) throw new Error();
    formatted = d.toLocaleString(undefined, DATE_FORMAT_OPTS);
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
      className="inline-flex items-center gap-1 rounded-full bg-primary/10 border border-primary/20 px-2 py-0.5 text-xs font-medium text-primary hover:bg-primary/20 transition-colors cursor-pointer"
      onClick={() =>
        onExpand(resolved, <FkRecordContent record={record} />)
      }
    >
      {resolved}
    </button>
  );
}

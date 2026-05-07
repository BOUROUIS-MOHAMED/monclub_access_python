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

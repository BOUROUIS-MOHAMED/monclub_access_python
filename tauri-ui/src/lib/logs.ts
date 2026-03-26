import type { LogLine } from "@/api/types";

export interface LogFilters {
  query: string;
  level: string;
  category: string;
  door: string;
  card: string;
  device: string;
  repeatedOnly: boolean;
}

function toText(value: unknown): string {
  if (value == null) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
}

function toInt(value: unknown, fallback: number): number {
  const parsed = Number.parseInt(toText(value), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function sanitizeTokenMap(value: unknown): Record<string, string> {
  if (!value || typeof value !== "object") {
    return {};
  }
  const entries = Object.entries(value as Record<string, unknown>);
  return entries.reduce<Record<string, string>>((acc, [key, tokenValue]) => {
    const normalizedKey = toText(key).trim();
    const normalizedValue = toText(tokenValue).trim();
    if (normalizedKey && normalizedValue) {
      acc[normalizedKey] = normalizedValue;
    }
    return acc;
  }, {});
}

function inferCategory(text: string, level: string, tokens: Record<string, string>): string {
  const lower = text.toLowerCase();
  if (tokens.door || tokens.cardId || tokens.userId) {
    return "ACCESS";
  }
  if (lower.includes("snapshot") || lower.includes("binding") || lower.includes("player") || lower.includes("screen") || lower.includes("monitor")) {
    return "TV";
  }
  if (lower.includes("update")) {
    return "UPDATE";
  }
  if (lower.includes("login") || lower.includes("logout") || lower.includes("auth")) {
    return "AUTH";
  }
  if (lower.includes("api")) {
    return "API";
  }
  if (["ERROR", "WARNING", "WARN", "CRITICAL"].includes(level)) {
    return "ALERT";
  }
  return "SYSTEM";
}

function extractToken(text: string, patterns: RegExp[]): string {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[1]) {
      return match[1].trim();
    }
  }
  return "";
}

export function inferLogTokens(text: string, level: string): Record<string, string> {
  const tokens: Record<string, string> = {
    level: level.toUpperCase() || "INFO",
  };

  const tokenMap: Record<string, RegExp[]> = {
    door: [/\bdoor(?:id|number)?\s*=\s*([^\s|,;]+)/i, /\bauthorizedoorid\s*=\s*([^\s|,;]+)/i],
    cardId: [/\bcardid\s*=\s*([^\s|,;]+)/i, /\bcardno\s*=\s*([^\s|,;]+)/i, /\bcode\s*=\s*([^\s|,;]+)/i],
    deviceId: [/\bdeviceid\s*=\s*([^\s|,;]+)/i],
    userId: [/\buserid\s*=\s*([^\s|,;]+)/i],
    mode: [/\bmode\s*=\s*([^\s|,;]+)/i],
  };

  for (const [key, patterns] of Object.entries(tokenMap)) {
    const value = extractToken(text, patterns);
    if (value) {
      tokens[key] = value;
    }
  }

  tokens.category = inferCategory(text, tokens.level, tokens);
  return tokens;
}

export function normalizeLogLine(payload: unknown): LogLine | null {
  if (payload == null) {
    return null;
  }

  if (typeof payload !== "object") {
    const rawText = toText(payload).trim();
    if (!rawText) {
      return null;
    }
    const tokens = inferLogTokens(rawText, "INFO");
    const timestamp = new Date().toISOString();
    return {
      id: `${timestamp}:INFO:${rawText}`,
      revision: 1,
      level: "INFO",
      text: rawText,
      rawText,
      repeatCount: 1,
      collapsed: false,
      ts: timestamp,
      firstSeenAt: timestamp,
      lastSeenAt: timestamp,
      tokens,
    };
  }

  const source = payload as Record<string, unknown>;
  const level = toText(source.level).trim().toUpperCase() || "INFO";
  const repeatCount = Math.max(1, toInt(source.repeatCount ?? source.count, 1));
  const rawText = (
    toText(source.rawText).trim()
    || toText(source.msg).trim()
    || toText(source.message).trim()
    || toText(source.text).trim()
  );
  const timestamp = (
    toText(source.ts).trim()
    || toText(source.firstSeenAt).trim()
    || toText(source.timestamp).trim()
    || new Date().toISOString()
  );
  const firstSeenAt = toText(source.firstSeenAt).trim() || timestamp;
  const lastSeenAt = toText(source.lastSeenAt).trim() || firstSeenAt;
  const baseText = toText(source.text).trim() || rawText;
  const displayText = repeatCount > 1 && baseText === rawText
    ? `${rawText} (x${repeatCount})`
    : baseText;
  const tokens = sanitizeTokenMap(source.tokens);
  const enrichedTokens = Object.keys(tokens).length > 0
    ? { ...tokens, category: tokens.category || inferCategory(rawText || displayText, level, tokens) }
    : inferLogTokens(rawText || displayText, level);

  const id = toText(source.id).trim() || `${level}:${firstSeenAt}:${rawText || displayText}`;
  const revision = Math.max(1, toInt(source.revision, repeatCount));

  return {
    id,
    revision,
    level,
    text: displayText || rawText || "(empty log line)",
    rawText: rawText || displayText || "(empty log line)",
    repeatCount,
    collapsed: repeatCount > 1,
    ts: timestamp,
    firstSeenAt,
    lastSeenAt,
    tokens: enrichedTokens,
  };
}

export function upsertLogLine(lines: LogLine[], incoming: LogLine, maxLines = 2000): LogLine[] {
  const incomingId = toText(incoming.id).trim();
  if (!incomingId) {
    const appended = [...lines, incoming];
    return appended.length > maxLines ? appended.slice(-maxLines) : appended;
  }

  const existingIndex = lines.findIndex((line) => toText(line.id).trim() === incomingId);
  if (existingIndex < 0) {
    const appended = [...lines, incoming];
    return appended.length > maxLines ? appended.slice(-maxLines) : appended;
  }

  const current = lines[existingIndex];
  if (
    toInt(current.revision, 0) === toInt(incoming.revision, 0)
    && toInt(current.repeatCount, 1) === toInt(incoming.repeatCount, 1)
    && toText(current.text) === toText(incoming.text)
    && toText(current.lastSeenAt) === toText(incoming.lastSeenAt)
  ) {
    return lines;
  }

  const next = lines.slice();
  next[existingIndex] = incoming;
  return next;
}

export function matchesLogLine(line: LogLine, filters: LogFilters): boolean {
  const level = toText(line.level).trim().toUpperCase() || "INFO";
  if (filters.level && filters.level !== "ALL" && level !== filters.level) {
    return false;
  }

  const tokens = sanitizeTokenMap(line.tokens);
  const category = toText(tokens.category).trim().toUpperCase() || inferCategory(toText(line.rawText || line.text), level, tokens);
  if (filters.category && filters.category !== "ALL" && category !== filters.category) {
    return false;
  }

  const repeatCount = Math.max(1, toInt(line.repeatCount, 1));
  if (filters.repeatedOnly && repeatCount <= 1) {
    return false;
  }

  const searchable = [
    toText(line.rawText || line.text),
    toText(line.text),
    level,
    toText(line.firstSeenAt || line.ts),
    ...Object.entries(tokens).map(([key, value]) => `${key}:${value}`),
  ].join(" ").toLowerCase();

  const query = filters.query.trim().toLowerCase();
  if (query && !searchable.includes(query)) {
    return false;
  }

  const door = filters.door.trim().toLowerCase();
  if (door && !(toText(tokens.door).toLowerCase().includes(door) || searchable.includes(`door=${door}`))) {
    return false;
  }

  const card = filters.card.trim().toLowerCase();
  if (card && !(toText(tokens.cardId).toLowerCase().includes(card) || searchable.includes(card))) {
    return false;
  }

  const device = filters.device.trim().toLowerCase();
  if (device && !(toText(tokens.deviceId).toLowerCase().includes(device) || searchable.includes(`deviceid=${device}`))) {
    return false;
  }

  return true;
}

export function formatLogClock(value: string | null | undefined): string {
  const raw = toText(value).trim();
  if (!raw) {
    return "--:--:--";
  }

  const isoMatch = raw.match(/T(\d{2}:\d{2}:\d{2})/);
  if (isoMatch?.[1]) {
    return isoMatch[1];
  }

  const plainMatch = raw.match(/\b(\d{2}:\d{2}:\d{2})\b/);
  if (plainMatch?.[1]) {
    return plainMatch[1];
  }

  const parsed = new Date(raw);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed.toLocaleTimeString();
  }

  return raw;
}

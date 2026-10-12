// Member fee lines on the entry screen (member fees F3, contract section 3; guide section 3.12).
// The PC judges each fee against its OWN local day with the gym's feeDueSoonDays, so the lines
// stay right offline over several days. Pure TypeScript (no React, no "@/" import, no enum) so
// node:test can run it: npm test.
//
// DISPLAY ONLY. Nothing here opens or shuts a door: a member the server blocks for an unpaid
// required fee is refused by the turnstile, and refused scans are not shown on this screen
// (SHOW_DENIED_ENTRIES in PopupWindow.tsx).

/** One fee line as the access engine sends it (sync_users.fees_json). */
export interface PopupFee {
  name: string;
  /** "YYYY-MM-DD", or null for a fee with no due date. */
  dueDate: string | null;
  required: boolean;
  paid: boolean;
}

export type FeeLineKind = "unpaid" | "dueSoon";

export interface FeeLine {
  kind: FeeLineKind;
  name: string;
  required: boolean;
  dueDate: string | null;
  /** dueSoon: whole days from today to the due date (0 = due today). unpaid: null. */
  daysLeft: number | null;
  title: string;
  action: string;
}

export interface FeeLinesView {
  /** At most MAX_FEE_LINES lines, most serious first. */
  shown: FeeLine[];
  /** How many lines are not shown. */
  more: number;
  /** "+1 autre" / "+N autres", or null when nothing is hidden. */
  moreText: string | null;
  /** The AMulti tile mark: "unpaid" when any fee is unpaid, else "dueSoon", else null. */
  mark: FeeLineKind | null;
}

export const DEFAULT_FEE_DUE_SOON_DAYS = 7;
export const MIN_FEE_DUE_SOON_DAYS = 1;
export const MAX_FEE_DUE_SOON_DAYS = 30;
export const MAX_FEE_LINES = 2;

const DAY_MS = 86400000;

/** "YYYY-MM-DD" (a longer ISO text is cut) -> days since 1970-01-01, or null when not a real date. */
export function dayNumber(iso: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(iso || ""));
  if (!m) return null;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  const t = Date.UTC(y, mo - 1, d);
  const back = new Date(t);
  if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d) return null;
  return Math.round(t / DAY_MS);
}

/** The PC's LOCAL calendar day of `now` as a day number (the gym's day, never UTC's). */
export function localDayNumber(now: Date): number {
  return Math.round(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate()) / DAY_MS);
}

/** The wire's fees, whatever their shape, as clean PopupFee items. Junk is dropped, never thrown. */
export function parseFees(raw: unknown): PopupFee[] {
  if (!Array.isArray(raw)) return [];
  const out: PopupFee[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const o = item as Record<string, unknown>;
    const name = typeof o.name === "string" ? o.name.trim() : "";
    if (!name) continue;
    const due = typeof o.dueDate === "string" && dayNumber(o.dueDate) != null ? o.dueDate.slice(0, 10) : null;
    out.push({ name, dueDate: due, required: o.required === true, paid: o.paid === true });
  }
  return out;
}

/** accessSoftwareSettings.feeDueSoonDays as the event carries it: 1-30, 7 when absent or unreadable. */
export function feeDueSoonDays(raw: unknown): number {
  const n = typeof raw === "number" ? raw : typeof raw === "string" && raw.trim() !== "" ? Number(raw) : NaN;
  if (!Number.isFinite(n)) return DEFAULT_FEE_DUE_SOON_DAYS;
  return Math.min(MAX_FEE_DUE_SOON_DAYS, Math.max(MIN_FEE_DUE_SOON_DAYS, Math.trunc(n)));
}

/**
 * One fee's status (contract section 3), with today = the PC's local day and N = feeDueSoonDays:
 * overdue = dueDate < today; unpaid = !paid or overdue; dueSoon = paid and today <= dueDate <= today + N.
 * Anything else needs no line (null).
 */
export function feeStatus(fee: PopupFee, today: Date, dueSoonDays: number): FeeLineKind | null {
  const t = localDayNumber(today);
  const due = fee.dueDate ? dayNumber(fee.dueDate) : null;
  const overdue = due != null && due < t;
  if (!fee.paid || overdue) return "unpaid";
  if (due != null && due >= t && due <= t + feeDueSoonDays(dueSoonDays)) return "dueSoon";
  return null;
}

function plural(n: number, one: string, many: string): string {
  return n > 1 ? many : one;
}

function lineFor(fee: PopupFee, kind: FeeLineKind, today: Date): FeeLine {
  if (kind === "unpaid") {
    return {
      kind, name: fee.name, required: fee.required, dueDate: fee.dueDate, daysLeft: null,
      title: "Frais « " + fee.name + " » impayé",
      action: "Passez à l'accueil pour le régler.",
    };
  }
  const due = fee.dueDate ? dayNumber(fee.dueDate) : null;
  const days = due == null ? 0 : Math.max(0, due - localDayNumber(today));
  const when = days === 0 ? "expire aujourd'hui" : "expire dans " + days + " " + plural(days, "jour", "jours");
  return {
    kind, name: fee.name, required: fee.required, dueDate: fee.dueDate, daysLeft: days,
    title: "Frais « " + fee.name + " » : " + when,
    action: "Passez à l'accueil pour le renouveler.",
  };
}

// unpaid required, then unpaid optional, then due soon
function rank(line: FeeLine): number {
  return line.kind === "unpaid" ? (line.required ? 0 : 1) : 2;
}

function sortDay(line: FeeLine): number {
  const d = line.dueDate ? dayNumber(line.dueDate) : null;
  return d == null ? Number.POSITIVE_INFINITY : d;
}

/**
 * Every line, most serious first: unpaid required, unpaid optional, then due soon (soonest first).
 * Ties: the older due date first (no date last), then the name.
 */
export function feeLines(fees: PopupFee[], today: Date, dueSoonDays: number): FeeLine[] {
  const lines: FeeLine[] = [];
  for (const fee of fees) {
    const kind = feeStatus(fee, today, dueSoonDays);
    if (kind) lines.push(lineFor(fee, kind, today));
  }
  return lines.sort((a, b) => {
    const r = rank(a) - rank(b);
    if (r !== 0) return r;
    const da = sortDay(a);
    const db = sortDay(b);
    if (da !== db) return da < db ? -1 : 1;
    return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  });
}

/** What AVerdict draws (at most two lines, then « +N autre(s) ») and the AMulti tile mark. */
export function feeLinesView(fees: PopupFee[], today: Date, dueSoonDays: number): FeeLinesView {
  const all = feeLines(fees, today, dueSoonDays);
  const shown = all.slice(0, MAX_FEE_LINES);
  const more = all.length - shown.length;
  return {
    shown,
    more,
    moreText: more > 0 ? "+" + more + " " + plural(more, "autre", "autres") : null,
    mark: all.length ? all[0].kind : null,
  };
}

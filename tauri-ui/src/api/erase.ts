// Erase-content wizard (lane 1, 2026-09-27) -- the local API it calls.
// Server side: app/core/erase_wizard.py, routes in access/local_api_routes.py (guide §3.2h).
import { get, post } from "@/api/client";

export type EraseProtocol = "ZK_PULLSDK" | "ZK_STANDALONE";
export type RefillOption = "now" | "auto" | "hold";
export type RunState = "RUNNING" | "DONE" | "FAILED" | "INCOMPLETE";

export interface EraseTableRow {
  key: string;
  count: number | null;
  erasable: boolean;
  reason?: string;
}

export interface EraseCounts {
  tables: Record<string, number | null>;
  extra: Record<string, number | null>;
}

export interface EraseHold {
  deviceId?: number;
  /** "erase-prep", "erase", or "erase-scheme-moved": held because the pin scheme moved before any
   *  delete -- « Remplir » is refused until the scheme is ``terminalScheme`` again (lane 1e). */
  reason?: string;
  runId?: string | null;
  since?: string | null;
  /** The scheme MonClub records now (what « Remplir » would write). */
  pinScheme?: string | null;
  /** Lane 1e: the scheme the terminal's pins were written under when the hold began; null when
   *  the row does not record it (written before lane 1e). */
  terminalScheme?: string | null;
}

export interface EraseStep {
  step: string;
  ok: boolean;
  at: string;
  [k: string]: unknown;
}

export interface EraseRun {
  runId: string;
  deviceId: number;
  device: { id: number; name: string; ip: string; port: string; protocol: EraseProtocol };
  protocol: EraseProtocol;
  tables: string[];
  forget: boolean | null;
  refill: RefillOption | null;
  backupOnly: boolean;
  state: RunState;
  step: string;
  steps: EraseStep[];
  countsBefore: EraseCounts | null;
  countsAfter: EraseCounts | null;
  backup: { path: string; sha256: string; rows: number; rowCounts: Record<string, number> } | null;
  progress: { phase: string; done: number; total: number } | null;
  error: string | null;
  holdKept: boolean | null;
  erased: boolean;
  pinScheme: string | null;
  otherPcsClosed?: boolean | null;
  /** Lane 1c: the pins accepted at step 1, and the people the run really left out (from its
   *  backup, before the first delete) -- pins only, never a name. */
  notRefilledAccepted?: string[] | null;
  notRefilled?: { count: number; pins: string[] } | null;
}

export interface ErasePreview {
  ok: true;
  previewId: string;
  device: { id: number; name: string; ip: string; port: string; protocol: EraseProtocol };
  pinScheme: string | null;
  tables: EraseTableRow[];
  extra: { admins?: number | null; faces?: number | null; passwords?: number | null };
  hold: EraseHold | null;
  run: EraseRun | null;
  limits: { doorLogs?: string; mbPinsPerPass?: number | null };
  /** What the refill would write (lane 1b): the server refuses an erase on a ``problem``
   *  (and, for "hold", on an ``accountProblem``). */
  refill?: EraseRefillCheck;
  /** Lane 1c (review C0): the people on the turnstile that the refill will NOT put back (not in
   *  its roster under ``scheme``; MB2000 administrators excluded -- the erase keeps them). null:
   *  the user list did not read, and the server refuses an erase. */
  notRefilled?: ErasePeopleLeftOut | null;
}

export interface ErasePeopleLeftOut {
  count: number;
  scheme: string | null;
  people: { pin: string; name: string | null }[];
}

export interface EraseRefillCheck {
  scheme: string | null;
  members: number | null;
  withheld: number | null;
  /** Under 'Par personne' (ACCOUNT), when the scheme now is another. */
  ifAccount?: { members: number; withheld: number };
  lastSyncOk: boolean;
  cacheUpdatedAt: string | null;
  problem: string | null;
  accountProblem: string | null;
  /** Lane 1c: why the member list is stale (REFILL_SOURCE_STALE) -- the last sync failed, none
   *  succeeded since Access started, or the last success is older than ``syncMaxAgeSec``. */
  staleWhy?: "NO_SYNC_YET" | "LAST_SYNC_FAILED" | "TOO_OLD" | null;
  /** Seconds since the last successful sync (monotonic clock); null when none. */
  lastSyncAgeSec?: number | null;
  /** max(3 x the sync interval, 10 min), in seconds. */
  syncMaxAgeSec?: number;
}

export interface EraseStartBody {
  previewId: string;
  tables: string[];
  forget?: boolean;
  refill?: RefillOption;
  typedName: string;
  password: string;
  acceptFaceLoss?: boolean;
  backupOnly?: boolean;
  /** Required (true) for an erase: the hold binds this PC only (lane 1b, review C0). */
  otherPcsClosed?: boolean;
  /** Required (true) for an erase when ``notRefilled.count`` > 0 (lane 1c, review C0). */
  acceptNotRefilled?: boolean;
}

export interface EraseHolds {
  ok: boolean;
  holds: EraseHold[];
  /** The start-up read of the holds failed: every turnstile is held until it reads. */
  loadFailed?: boolean;
}

export interface RefillResult {
  ok: boolean;
  pinScheme: string | null;
  passRequested: boolean;
  invalidated?: number;
  /** Lane 1b: the backups' 30 days now count from this Refill (false: a mark could not be written). */
  backupsMarked?: boolean;
  /** Lane 1c (review F1): what this refill writes, under the scheme it pushes -- reported, never a
   *  refusal (``problem``: REFILL_SOURCE_MISSING / _STALE / _EMPTY, REFILL_WITHHELD). */
  refill?: {
    scheme: string | null; members: number | null; withheld: number | null; problem: string | null;
    staleWhy?: string | null; lastSyncAgeSec?: number | null; syncMaxAgeSec?: number;
  };
  /** MB2000 administrators the refill writes members over (confirmed with ``confirmAdminPins``). */
  adminPins?: string[];
  adminCheck?: "CHECKED" | "NOT_APPLICABLE" | "UNREADABLE";
}

export interface EraseApi {
  verifyPassword(password: string): Promise<{ ok: boolean; error?: string }>;
  preview(deviceId: number): Promise<ErasePreview>;
  start(deviceId: number, body: EraseStartBody): Promise<{ ok: boolean; runId: string }>;
  status(): Promise<{ ok: boolean; running: boolean; run: EraseRun | null }>;
  /** ``expectedPinScheme``: the scheme the page SHOWED (read from holds()); the server refuses
   *  with 409 PIN_SCHEME_CHANGED when it moved since. ``confirmAdminPins``: the administrator
   *  pins a 409 ADMIN_PIN_IN_ROSTER named, confirmed by the operator (lane 1c). */
  refill(deviceId: number, password: string, expectedPinScheme: string | null,
         confirmAdminPins?: string[]): Promise<RefillResult>;
  holds(): Promise<EraseHolds>;
}

export const liveEraseApi: EraseApi = {
  verifyPassword: (password) =>
    post<{ ok: boolean; error?: string }>("/auth/verify-admin-password", { password }, 25_000),
  preview: (deviceId) => get<ErasePreview>(`/devices/${deviceId}/erase/preview`),
  start: (deviceId, body) =>
    // The server checks the password AND the gym's switch (15 s each at worst) before it answers.
    post<{ ok: boolean; runId: string }>(`/devices/${deviceId}/erase`, body, 60_000),
  status: () => get<{ ok: boolean; running: boolean; run: EraseRun | null }>("/erase/status"),
  refill: (deviceId, password, expectedPinScheme, confirmAdminPins) =>
    post<RefillResult>(`/devices/${deviceId}/erase/refill`,
      { password, expectedPinScheme, ...(confirmAdminPins ? { confirmAdminPins } : {}) }, 30_000),
  holds: () => get<EraseHolds>("/erase/holds"),
};

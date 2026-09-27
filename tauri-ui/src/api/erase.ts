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
  reason?: string;
  runId?: string | null;
  since?: string | null;
  pinScheme?: string | null;
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
}

export interface EraseApi {
  verifyPassword(password: string): Promise<{ ok: boolean; error?: string }>;
  preview(deviceId: number): Promise<ErasePreview>;
  start(deviceId: number, body: EraseStartBody): Promise<{ ok: boolean; runId: string }>;
  status(): Promise<{ ok: boolean; running: boolean; run: EraseRun | null }>;
  /** ``expectedPinScheme``: the scheme the page SHOWED (read from holds()); the server refuses
   *  with 409 PIN_SCHEME_CHANGED when it moved since. */
  refill(deviceId: number, password: string, expectedPinScheme: string | null): Promise<RefillResult>;
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
  refill: (deviceId, password, expectedPinScheme) =>
    post<RefillResult>(`/devices/${deviceId}/erase/refill`, { password, expectedPinScheme }, 30_000),
  holds: () => get<EraseHolds>("/erase/holds"),
};

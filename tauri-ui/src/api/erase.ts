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
}

export interface EraseApi {
  verifyPassword(password: string): Promise<{ ok: boolean; error?: string }>;
  preview(deviceId: number): Promise<ErasePreview>;
  start(deviceId: number, body: EraseStartBody): Promise<{ ok: boolean; runId: string }>;
  status(): Promise<{ ok: boolean; running: boolean; run: EraseRun | null }>;
  refill(deviceId: number, password: string): Promise<{ ok: boolean; pinScheme: string | null; passRequested: boolean }>;
  holds(): Promise<{ ok: boolean; holds: EraseHold[] }>;
}

export const liveEraseApi: EraseApi = {
  verifyPassword: (password) =>
    post<{ ok: boolean; error?: string }>("/auth/verify-admin-password", { password }, 25_000),
  preview: (deviceId) => get<ErasePreview>(`/devices/${deviceId}/erase/preview`),
  start: (deviceId, body) =>
    post<{ ok: boolean; runId: string }>(`/devices/${deviceId}/erase`, body, 30_000),
  status: () => get<{ ok: boolean; running: boolean; run: EraseRun | null }>("/erase/status"),
  refill: (deviceId, password) =>
    post<{ ok: boolean; pinScheme: string | null; passRequested: boolean }>(
      `/devices/${deviceId}/erase/refill`, { password }, 30_000),
  holds: () => get<{ ok: boolean; holds: EraseHold[] }>("/erase/holds"),
};

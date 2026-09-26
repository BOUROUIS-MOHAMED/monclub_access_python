// P3b-2: driver/reader roles, reader screens and requests to the driver PC
// (local routes under /api/v2/realtime/*, see access/v2_routes.py).
import { ApiError, get, post } from "./client";

export type RealtimeRole = "DRIVER" | "READER" | "ALL_TURNSTILES" | "UNKNOWN";

export interface RealtimeDrive {
  gymDeviceId: number;
  name: string;
  generation: number;
  state: "DRIVE" | "WAIT_FOR_RELEASE" | string;
  handoverForced: boolean;
  addOnly: boolean;
}

export interface RealtimeStatus {
  availability: "ON" | "OFF" | "UNKNOWN" | "NOT_STARTED" | string;
  role: RealtimeRole | string;
  mode: "ALL" | "LEASED" | string;
  source?: string;
  drive: RealtimeDrive[];
  release: { gymDeviceId: number; name: string; generation: number }[];
  readerOf: { pcId: number; name: string }[];
  socket?: { connected: boolean; sessions: number; lastClose?: string | null; lastError?: string | null; pollIntervalSec?: number };
  clock?: { offsetSec: number; samples: number; source: string } | null;
  commands?: { running: string[]; claimed?: number; succeeded?: number; failed?: number; refused?: number; interrupted?: number };
  lastError?: string | null;
}

export interface ReaderDoorEvent {
  id: number;
  gymDeviceId: number;
  deviceName: string;
  driverPcId: number;
  doorId: number | null;
  direction: string | null;
  date: string;
  type: string;
  allowed: boolean | null;
  reason: string | null;
  userId: number | null;
  userName: string | null;
}

export interface ReaderHistoryPage {
  available: boolean;
  turnstiles: { gymDeviceId: number; name: string; driverPcId: number; driverPcName: string }[];
  items: ReaderDoorEvent[];
  nextBeforeId: number | null;
}

export interface EnrollTurnstile {
  gymDeviceId: number;
  name: string;
  driverPcName: string | null;
  status: "THIS_PC" | "PENDING_DRIVER" | string;
}

export const realtime = {
  status: () => get<RealtimeStatus>("/realtime/status"),
  readerHistory: (beforeId?: number | null, limit = 50) => {
    const params: Record<string, string> = { limit: String(limit) };
    if (beforeId) params.beforeId = String(beforeId);
    return get<ReaderHistoryPage>("/realtime/reader/door-history", params);
  },
  enrollTurnstiles: () => get<{ role: string; turnstiles: EnrollTurnstile[] }>("/realtime/enroll/turnstiles"),
  requestDoor: (deviceId: number, doorNumber = 1) =>
    post<{ ok: boolean; commandId: string; targetPcId: number; targetConnected: boolean }>(
      `/realtime/devices/${deviceId}/door/request`, { doorNumber }),
  requestResync: (deviceId: number) =>
    post<{ ok: boolean; commandId: string; targetPcId: number; targetConnected: boolean }>(
      `/realtime/devices/${deviceId}/resync/request`, {}),
};

/** The local API refused a device action because another PC drives that turnstile. */
export function isNotDriverError(e: unknown): boolean {
  return e instanceof ApiError && e.status === 409 && e.payload?.notDriver === true;
}

export const ROLE_LABEL_FR: Record<string, string> = {
  DRIVER: "PC pilote",
  READER: "PC lecteur",
  ALL_TURNSTILES: "Tous les tourniquets (sans affectation)",
  UNKNOWN: "Inconnu",
};

/** Ask the driver PC (through the server) to open a door this PC does not drive. */
/** The local door route answers 202 `requested` when another PC drives the turnstile. */
export function doorRequestedMessage(res: { targetConnected?: boolean }): string {
  return res.targetConnected
    ? "Demande envoyée au PC pilote. Son résultat n'est pas visible ici."
    : "Demande enregistrée, mais le PC pilote n'est pas connecté : elle expirera sans ouvrir.";
}

export async function requestDoorViaDriver(deviceId: number, doorNumber: number): Promise<string> {
  const res = await realtime.requestDoor(deviceId, doorNumber);
  return res.targetConnected
    ? "Demande envoyée au PC pilote. Son résultat n'est pas visible ici."
    : "Demande enregistrée, mais le PC pilote n'est pas connecté : elle expirera sans ouvrir.";
}

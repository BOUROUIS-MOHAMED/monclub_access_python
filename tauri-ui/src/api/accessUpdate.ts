// Access update API — wraps /api/v2/update/* endpoints
import { get, post } from "@/api/client";
import type { UpdateRollbackResponse, UpdateStatusResponse, UpdateVersionInfoResponse } from "@/api/types";

export function getAccessUpdateStatus(): Promise<UpdateStatusResponse> {
  return get<UpdateStatusResponse>("/update/status");
}

export function checkAccessUpdate(): Promise<{ ok: boolean }> {
  return post("/update/check", {});
}

export function downloadAccessUpdate(): Promise<{ ok: boolean }> {
  return post("/update/download", {});
}

export function installAccessUpdate(): Promise<{ ok: boolean; message?: string }> {
  return post("/update/install", {});
}

/** Answers OK only once the restore helper runs; the app then quits and restarts on `previousVersion`. */
export function rollbackAccessUpdate(body: { previousVersion: string; currentVersion: string }): Promise<UpdateRollbackResponse> {
  return post("/update/rollback", body);
}

export function cancelAccessUpdate(): Promise<{ ok: boolean }> {
  return post("/update/cancel", {});
}

export function getAccessVersionInfo(): Promise<UpdateVersionInfoResponse> {
  return get<UpdateVersionInfoResponse>("/update/version");
}

// Access update API — wraps /api/v2/update/* endpoints
import { get, post } from "@/api/client";
import type { UpdateStatusResponse, UpdateVersionInfoResponse } from "@/api/types";

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

export function cancelAccessUpdate(): Promise<{ ok: boolean }> {
  return post("/update/cancel", {});
}

export function getAccessVersionInfo(): Promise<UpdateVersionInfoResponse> {
  return get<UpdateVersionInfoResponse>("/update/version");
}

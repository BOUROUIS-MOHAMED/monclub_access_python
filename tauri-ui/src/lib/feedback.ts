import type { AppConfig, FeedbackEventType } from "@/api/types";
import { del, getApiBaseUrl, getAuthToken } from "@/api/client";
import { LOCAL_API_PREFIX } from "@/config/appConst";

export type FeedbackSoundKind =
  | "device-push"
  | "sync-complete"
  | "anti-fraud-duration"
  | "anti-fraud-daily-limit";

export const DEFAULT_FEEDBACK_SOUNDS: Record<FeedbackEventType, string> = {
  device_push_success: "/sounds/device-push-success.mp3",
  sync_completed_success: "/sounds/sync-complete-success.mp3",
  anti_fraud_duration: "/sounds/anti-fraud-duration-default.mp3",
  anti_fraud_daily_limit: "/sounds/anti-fraud-daily-limit-default.mp3",
};

export const DEFAULT_FEEDBACK_ANIMATIONS: Record<FeedbackEventType, string> = {
  device_push_success: "/animations/device-push-celebration.json",
  sync_completed_success: "/animations/sync-complete-confetti.json",
  // Anti-fraud events are alerts, not celebrations — no animations.
  anti_fraud_duration: "",
  anti_fraud_daily_limit: "",
};

export function getFeedbackSoundKind(eventType: FeedbackEventType): FeedbackSoundKind {
  switch (eventType) {
    case "device_push_success": return "device-push";
    case "sync_completed_success": return "sync-complete";
    case "anti_fraud_duration": return "anti-fraud-duration";
    case "anti_fraud_daily_limit": return "anti-fraud-daily-limit";
  }
}

export function isFeedbackSoundEnabled(cfg: AppConfig | null, eventType: FeedbackEventType): boolean {
  if (!cfg) return false;
  switch (eventType) {
    case "device_push_success": return Boolean(cfg.push_success_sound_enabled);
    case "sync_completed_success": return Boolean(cfg.sync_success_sound_enabled);
    // Anti-fraud sounds follow the same per-app enable/disable toggle as sync
    // sounds for now — if an operator has sync sounds off for a quiet floor
    // they probably want anti-fraud sounds off too. Can be split later.
    case "anti_fraud_duration":
    case "anti_fraud_daily_limit":
      return Boolean(cfg.sync_success_sound_enabled);
  }
}

export function isFeedbackAnimationEnabled(cfg: AppConfig | null, eventType: FeedbackEventType): boolean {
  if (!cfg) return false;
  switch (eventType) {
    case "device_push_success": return Boolean(cfg.push_success_animation_enabled);
    case "sync_completed_success": return Boolean(cfg.sync_success_animation_enabled);
    // Anti-fraud events have no animation by design.
    case "anti_fraud_duration":
    case "anti_fraud_daily_limit":
      return false;
  }
}

export function getFeedbackSoundSource(cfg: AppConfig | null, eventType: FeedbackEventType): "default" | "custom" {
  if (!cfg) return "default";
  switch (eventType) {
    case "device_push_success": return cfg.push_success_sound_source;
    case "sync_completed_success": return cfg.sync_success_sound_source;
    case "anti_fraud_duration": return cfg.anti_fraud_duration_sound_source;
    case "anti_fraud_daily_limit": return cfg.anti_fraud_daily_limit_sound_source;
  }
}

export function getFeedbackCustomSoundPath(cfg: AppConfig | null, eventType: FeedbackEventType): string {
  if (!cfg) return "";
  switch (eventType) {
    case "device_push_success": return String(cfg.push_success_custom_sound_path || "");
    case "sync_completed_success": return String(cfg.sync_success_custom_sound_path || "");
    case "anti_fraud_duration": return String(cfg.anti_fraud_duration_custom_sound_path || "");
    case "anti_fraud_daily_limit": return String(cfg.anti_fraud_daily_limit_custom_sound_path || "");
  }
}

export function buildCustomFeedbackSoundUrl(kind: FeedbackSoundKind, versionHint = ""): string {
  const token = getAuthToken();
  const url = new URL(`${getApiBaseUrl()}${LOCAL_API_PREFIX}/feedback/sounds/${kind}`);
  if (token) {
    url.searchParams.set("token", token);
  }
  if (versionHint) {
    url.searchParams.set("v", versionHint);
  }
  return url.toString();
}

export function getFeedbackSoundUrl(cfg: AppConfig | null, eventType: FeedbackEventType): string {
  const kind = getFeedbackSoundKind(eventType);
  const source = getFeedbackSoundSource(cfg, eventType);
  const versionHint = getFeedbackCustomSoundPath(cfg, eventType);
  if (source === "custom" && versionHint) {
    return buildCustomFeedbackSoundUrl(kind, versionHint);
  }
  return DEFAULT_FEEDBACK_SOUNDS[eventType];
}

export function currentFeedbackFileName(pathValue: unknown): string {
  const raw = String(pathValue || "").trim();
  if (!raw) return "";
  const normalized = raw.replace(/\\/g, "/");
  const parts = normalized.split("/");
  return parts[parts.length - 1] || raw;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  let binary = "";
  for (let index = 0; index < bytes.length; index += chunkSize) {
    const chunk = bytes.subarray(index, index + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

async function parseJsonResponse<T>(response: Response): Promise<T> {
  const text = await response.text();
  let payload: any = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }
  if (!response.ok || payload?.ok === false) {
    throw new Error(payload?.error || text || `HTTP ${response.status}`);
  }
  return payload as T;
}

function jsonHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };
  const token = getAuthToken();
  if (token) {
    headers["X-Local-Token"] = token;
  }
  return headers;
}

export async function uploadFeedbackSound(
  kind: FeedbackSoundKind,
  file: File,
): Promise<{ ok: boolean; fileName: string; path: string; sizeBytes: number }> {
  const contentBase64 = arrayBufferToBase64(await file.arrayBuffer());
  const response = await fetch(`${getApiBaseUrl()}${LOCAL_API_PREFIX}/feedback/sounds/${kind}`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      fileName: file.name,
      contentBase64,
    }),
  });
  return parseJsonResponse(response);
}

export async function resetFeedbackSound(kind: FeedbackSoundKind): Promise<{ ok: boolean }> {
  return del<{ ok: boolean }>(`/feedback/sounds/${kind}`);
}

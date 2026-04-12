import type { AppConfig, FeedbackEventType } from "@/api/types";
import { del, getApiBaseUrl, getAuthToken } from "@/api/client";
import { LOCAL_API_PREFIX } from "@/config/appConst";

export type FeedbackSoundKind = "device-push" | "sync-complete";

export const DEFAULT_FEEDBACK_SOUNDS: Record<FeedbackEventType, string> = {
  device_push_success: "/sounds/device-push-success.mp3",
  sync_completed_success: "/sounds/sync-complete-success.mp3",
};

export const DEFAULT_FEEDBACK_ANIMATIONS: Record<FeedbackEventType, string> = {
  device_push_success: "/animations/device-push-celebration.json",
  sync_completed_success: "/animations/sync-complete-confetti.json",
};

export function getFeedbackSoundKind(eventType: FeedbackEventType): FeedbackSoundKind {
  return eventType === "device_push_success" ? "device-push" : "sync-complete";
}

export function isFeedbackSoundEnabled(cfg: AppConfig | null, eventType: FeedbackEventType): boolean {
  if (!cfg) return false;
  return eventType === "device_push_success"
    ? Boolean(cfg.push_success_sound_enabled)
    : Boolean(cfg.sync_success_sound_enabled);
}

export function isFeedbackAnimationEnabled(cfg: AppConfig | null, eventType: FeedbackEventType): boolean {
  if (!cfg) return false;
  return eventType === "device_push_success"
    ? Boolean(cfg.push_success_animation_enabled)
    : Boolean(cfg.sync_success_animation_enabled);
}

export function getFeedbackSoundSource(cfg: AppConfig | null, eventType: FeedbackEventType): "default" | "custom" {
  if (!cfg) return "default";
  return eventType === "device_push_success"
    ? cfg.push_success_sound_source
    : cfg.sync_success_sound_source;
}

export function getFeedbackCustomSoundPath(cfg: AppConfig | null, eventType: FeedbackEventType): string {
  if (!cfg) return "";
  return eventType === "device_push_success"
    ? String(cfg.push_success_custom_sound_path || "")
    : String(cfg.sync_success_custom_sound_path || "");
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

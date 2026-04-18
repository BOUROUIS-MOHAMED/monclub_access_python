import { getApiBaseUrl } from "@/api/client";
import type { PopupEvent } from "@/api/types";
import { LOCAL_API_PREFIX } from "@/config/appConst";

const LEGACY_DASHBOARD_AVATAR_RE =
  /^\/?assets\/(?:avatars|images\/avatar)\/avatar-(\d+)\.(?:png|jpe?g|webp)$/i;

export function normalizePopupImageSource(raw: string): string {
  const value = String(raw || "").trim();
  if (!value) return "";
  const avatarMatch = value.match(LEGACY_DASHBOARD_AVATAR_RE);
  if (avatarMatch) {
    return `/assets/images/avatar/avatar-${avatarMatch[1]}.webp`;
  }
  return value;
}

export function buildPopupImageCandidates(
  popup: Pick<PopupEvent, "userImage" | "userProfileImage" | "imagePath">,
): string[] {
  const candidates: string[] = [];
  const primary = normalizePopupImageSource(popup.userImage || popup.imagePath || "");
  const fallback = normalizePopupImageSource(popup.userProfileImage || "");
  if (primary) candidates.push(primary);
  if (fallback && fallback !== primary) candidates.push(fallback);
  return candidates;
}

export function toPopupCachedImageUrl(raw: string): string {
  const normalized = normalizePopupImageSource(raw);
  if (!normalized) return "";
  if (normalized.startsWith("data:")) return normalized;
  return `${getApiBaseUrl()}${LOCAL_API_PREFIX}/image-cache?url=${encodeURIComponent(normalized)}`;
}

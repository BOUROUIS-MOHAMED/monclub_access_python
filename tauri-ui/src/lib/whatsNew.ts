import type { ACCESS_CHANGELOG } from "../whats-new/access-changelog.ts";

export function shouldShowWhatsNew(
  current: string,
  lastShown: string | null,
  changelog: typeof ACCESS_CHANGELOG,
): (typeof ACCESS_CHANGELOG)[number]["items"] | null {
  if (current === lastShown) return null;
  const items = changelog.find((release) => release.version === current)?.items;
  return items?.length ? items : null;
}

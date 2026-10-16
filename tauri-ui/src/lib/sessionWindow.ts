// Profil's session row (Card P, guide §3.13): the stored access token's window,
// sessionIssuedAt -> sessionExpiresAt from /status. Pure TypeScript so node:test
// can run it.

const DAY_MS = 86_400_000;

export interface TokenWindow {
  /** Whole days left, floored like the server's loginDaysRemaining. */
  daysLeft: number;
  /** Share of the token's life still ahead, 0-100, for the bar. */
  pctLeft: number;
}

/** Null when either end is missing or unreadable, or the window is empty. */
export function tokenWindow(
  issued: string | null | undefined,
  expires: string | null | undefined,
  now: number = Date.now(),
): TokenWindow | null {
  if (!issued || !expires) return null;
  const start = Date.parse(issued);
  const end = Date.parse(expires);
  if (isNaN(start) || isNaN(end) || end <= start) return null;
  const left = Math.max(0, end - now);
  return {
    daysLeft: Math.floor(left / DAY_MS),
    pctLeft: Math.round((Math.min(left, end - start) / (end - start)) * 100),
  };
}

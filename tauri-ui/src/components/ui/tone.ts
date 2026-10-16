// Access v5 tones — the MonClub web dashboard's semantic colours.
// Every class string is written out in full so Tailwind's scanner sees it.
//   soft  = 16 % tint background + ink text (chips, icon tiles, pills)
//   ink   = the text colour that sits on a soft tint (dark shade / light in dark mode)
//   dot   = the main shade (status dots, bars)
//   solid = filled badge (white text)

export type Tone = "primary" | "success" | "warning" | "error" | "info" | "grey";

export const SOFT: Record<Tone, string> = {
  primary: "bg-primary/16 text-primary-ink",
  success: "bg-success/16 text-success-ink",
  warning: "bg-warning/16 text-warning-ink",
  error: "bg-error/16 text-error-ink",
  info: "bg-info/16 text-info-ink",
  grey: "bg-grey/16 text-grey-ink",
};

export const INK: Record<Tone, string> = {
  primary: "text-primary-ink",
  success: "text-success-ink",
  warning: "text-warning-ink",
  error: "text-error-ink",
  info: "text-info-ink",
  grey: "text-muted-foreground",
};

export const DOT: Record<Tone, string> = {
  primary: "bg-primary",
  success: "bg-success",
  warning: "bg-warning",
  error: "bg-error",
  info: "bg-info",
  grey: "bg-grey/60",
};

export const SOLID: Record<Tone, string> = {
  primary: "bg-primary text-primary-foreground",
  success: "bg-success text-white",
  warning: "bg-warning text-foreground",
  error: "bg-error text-white",
  info: "bg-info text-white",
  grey: "bg-grey text-white",
};

/** Two-letter initials ("Yassine Gharbi" → "YG"), "—" when empty. */
export function initialsOf(name: string): string {
  const p = (name || "").trim().split(/\s+/).filter(Boolean);
  if (!p.length) return "—";
  return ((p[0][0] || "") + (p.length > 1 ? p[p.length - 1][0] : "")).toUpperCase();
}

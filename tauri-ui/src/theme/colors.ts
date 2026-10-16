type TokenSet = Record<string, string>;
type ThemeMode = "light" | "dark";
type DesktopRole = "access" | "tv";
type ThemeColorSet = Record<ThemeMode, TokenSet>;

// ── Access v5 palette ──────────────────────────────────────────────────────
// Owner decision for the v5 redesign: match the MonClub web dashboard (Minimals
// palette), not the old red brand. Hex → HSL for the tokens the whole app reads:
//   #1877F2 primary · #0C44AE primary dark · #1C252E ink · #637381 muted text
//   #F4F6F8 grey surface · #919EAB grey · borders = rgba(145,158,171,.24/.32)
//   flattened on white (the tokens are opaque HSL triplets).
// Tone tokens (success / warning / error / info / grey): `<tone>` is the main
// shade (dots, bars, solid fills, 16 % soft tints); `<tone>Ink` is the text
// colour used ON a soft tint — the dark shade in light mode, the light shade in
// dark mode (a dark shade on a dark tint would be unreadable).
// `dark` is not in the design: a sober dark version of the same palette
// (Minimals dark neutrals #141A21 / #1C252E, same blue).
export const accessThemeColors = {
  light: {
    background: "0 0% 100%",
    foreground: "210 24% 14.5%",
    card: "0 0% 100%",
    cardForeground: "210 24% 14.5%",
    popover: "0 0% 100%",
    popoverForeground: "210 24% 14.5%",
    primary: "214 89% 52%",
    primaryForeground: "0 0% 100%",
    primaryInk: "219 87% 36%",
    secondary: "210 22% 96.5%",
    secondaryForeground: "210 24% 14.5%",
    muted: "210 22% 96.5%",
    mutedForeground: "208 13% 45%",
    accent: "214 89% 96%",
    accentForeground: "219 87% 36%",
    destructive: "11 100% 59%",
    destructiveForeground: "0 0% 100%",
    border: "210 13% 91%",
    input: "210 13% 88%",
    ring: "214 89% 52%",
    success: "142 71% 45%",
    successInk: "154 78% 31%",
    warning: "40 100% 50%",
    warningInk: "36 100% 36%",
    error: "11 100% 59%",
    errorInk: "2 77% 41%",
    info: "189 100% 43%",
    infoInk: "198 100% 31%",
    grey: "210 13% 62%",
    greyInk: "208 13% 45%",
    chart1: "214 89% 52%",
    chart2: "142 71% 45%",
    chart3: "40 100% 50%",
    chart4: "189 100% 43%",
    chart5: "210 24% 14.5%",
    sidebar: "0 0% 100%",
    sidebarForeground: "210 24% 14.5%",
    sidebarPrimary: "214 89% 52%",
    sidebarPrimaryForeground: "0 0% 100%",
    sidebarAccent: "214 89% 96%",
    sidebarAccentForeground: "214 89% 52%",
    sidebarBorder: "210 13% 91%",
    sidebarRing: "214 89% 52%",
  },
  dark: {
    background: "212 25% 10%",
    foreground: "0 0% 100%",
    card: "210 24% 14.5%",
    cardForeground: "0 0% 100%",
    popover: "210 24% 14.5%",
    popoverForeground: "0 0% 100%",
    primary: "214 89% 52%",
    primaryForeground: "0 0% 100%",
    primaryInk: "209 94% 72%",
    secondary: "208 20% 18%",
    secondaryForeground: "0 0% 100%",
    muted: "208 20% 18%",
    mutedForeground: "210 13% 62%",
    accent: "208 20% 18%",
    accentForeground: "0 0% 100%",
    destructive: "11 100% 59%",
    destructiveForeground: "0 0% 100%",
    border: "214 15% 21%",
    input: "214 15% 24%",
    ring: "214 89% 52%",
    success: "142 71% 45%",
    successInk: "130 77% 70%",
    warning: "40 100% 50%",
    warningInk: "44 100% 70%",
    error: "11 100% 59%",
    errorInk: "20 100% 75%",
    info: "189 100% 43%",
    infoInk: "180 86% 67%",
    grey: "210 13% 62%",
    greyInk: "208 17% 80%",
    chart1: "214 89% 52%",
    chart2: "142 71% 45%",
    chart3: "40 100% 50%",
    chart4: "189 100% 43%",
    chart5: "0 0% 100%",
    sidebar: "212 25% 10%",
    sidebarForeground: "0 0% 100%",
    sidebarPrimary: "214 89% 52%",
    sidebarPrimaryForeground: "0 0% 100%",
    sidebarAccent: "208 20% 18%",
    sidebarAccentForeground: "209 94% 72%",
    sidebarBorder: "214 15% 21%",
    sidebarRing: "214 89% 52%",
  },
} as const satisfies ThemeColorSet;

export const tvThemeColors = {
  light: {
    background: "30 100% 98%",
    foreground: "24 18% 14%",
    card: "0 0% 100%",
    cardForeground: "24 18% 14%",
    popover: "0 0% 100%",
    popoverForeground: "24 18% 14%",
    primary: "28 96% 52%",
    primaryForeground: "0 0% 100%",
    secondary: "32 100% 94%",
    secondaryForeground: "24 18% 14%",
    muted: "34 42% 94%",
    mutedForeground: "24 10% 40%",
    accent: "30 100% 94%",
    accentForeground: "24 18% 14%",
    destructive: "0 72% 51%",
    destructiveForeground: "0 0% 100%",
    border: "30 28% 86%",
    input: "30 28% 86%",
    ring: "28 96% 52%",
    chart1: "28 96% 52%",
    chart2: "38 92% 60%",
    chart3: "18 78% 58%",
    chart4: "0 72% 51%",
    chart5: "24 18% 22%",
    sidebar: "30 100% 97%",
    sidebarForeground: "24 18% 14%",
    sidebarPrimary: "28 96% 52%",
    sidebarPrimaryForeground: "0 0% 100%",
    sidebarAccent: "34 42% 94%",
    sidebarAccentForeground: "24 18% 14%",
    sidebarBorder: "30 28% 86%",
    sidebarRing: "28 96% 52%",
  },
  dark: {
    background: "24 15% 7%",
    foreground: "33 40% 95%",
    card: "24 13% 10%",
    cardForeground: "33 40% 95%",
    popover: "24 13% 10%",
    popoverForeground: "33 40% 95%",
    primary: "32 96% 58%",
    primaryForeground: "24 15% 7%",
    secondary: "24 10% 15%",
    secondaryForeground: "33 40% 95%",
    muted: "24 11% 13%",
    mutedForeground: "28 14% 66%",
    accent: "24 10% 15%",
    accentForeground: "33 40% 95%",
    destructive: "0 72% 51%",
    destructiveForeground: "0 0% 100%",
    border: "24 10% 19%",
    input: "24 10% 15%",
    ring: "32 96% 58%",
    chart1: "32 96% 58%",
    chart2: "41 92% 61%",
    chart3: "18 78% 58%",
    chart4: "0 72% 51%",
    chart5: "33 40% 95%",
    sidebar: "24 15% 8%",
    sidebarForeground: "33 40% 95%",
    sidebarPrimary: "32 96% 58%",
    sidebarPrimaryForeground: "24 15% 7%",
    sidebarAccent: "24 10% 15%",
    sidebarAccentForeground: "33 40% 95%",
    sidebarBorder: "24 10% 16%",
    sidebarRing: "32 96% 58%",
  },
} as const satisfies ThemeColorSet;

export const desktopThemeColors = {
  access: accessThemeColors,
  tv: tvThemeColors,
} as const satisfies Record<DesktopRole, ThemeColorSet>;

function toCssVarName(tokenKey: string): string {
  return `--${tokenKey.replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`)}`;
}

function toCssBlock(selector: string, tokens: TokenSet): string {
  const lines = Object.entries(tokens).map(([key, value]) => `  ${toCssVarName(key)}: ${value};`);
  return `${selector} {\n${lines.join("\n")}\n}`;
}

export function installSemanticTokenStyles(doc: Document = document): void {
  if (!doc?.head) return;

  const styleId = "monclub-semantic-tokens";
  const cssBlocks = [
    toCssBlock(":root", accessThemeColors.light),
    toCssBlock(".dark", accessThemeColors.dark),
  ];

  (Object.entries(desktopThemeColors) as Array<[DesktopRole, ThemeColorSet]>).forEach(([role, colors]) => {
    cssBlocks.push(toCssBlock(`html[data-desktop-role="${role}"]`, colors.light));
    cssBlocks.push(toCssBlock(`html[data-desktop-role="${role}"].dark`, colors.dark));
  });

  let styleEl = doc.getElementById(styleId) as HTMLStyleElement | null;
  if (!styleEl) {
    styleEl = doc.createElement("style");
    styleEl.id = styleId;
    doc.head.appendChild(styleEl);
  }

  styleEl.textContent = cssBlocks.join("\n\n");
}

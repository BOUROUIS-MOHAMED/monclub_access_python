type TokenSet = Record<string, string>;
type ThemeMode = "light" | "dark";
type DesktopRole = "access" | "tv";
type ThemeColorSet = Record<ThemeMode, TokenSet>;

// ── Access v3 palette ──────────────────────────────────────────────────────
// Rebased from the Claude Design "Access v3" refonte, which replaces the old
// orange accent with the brand red #E2203F. Hex → HSL for the tokens the whole
// app reads:
//   #F5F5F5 page · #FFFFFF card/sidebar · #121A1C ink · #4A5056 muted
//   #E2203F primary · #B81A33 primary-on-light · #F7F7F9 surface
// The design is a LIGHT interface; `light` below reproduces it. `dark` keeps
// its existing neutrals and only swaps the orange accents to the same red, so
// the theme toggle still yields a coherent screen.
export const accessThemeColors = {
  light: {
    background: "0 0% 96%",
    foreground: "192 22% 9%",
    card: "0 0% 100%",
    cardForeground: "192 22% 9%",
    popover: "0 0% 100%",
    popoverForeground: "192 22% 9%",
    primary: "350 77% 51%",
    primaryForeground: "0 0% 100%",
    secondary: "240 14% 97%",
    secondaryForeground: "192 22% 9%",
    muted: "240 14% 97%",
    mutedForeground: "210 8% 31%",
    accent: "350 77% 96%",
    accentForeground: "350 75% 41%",
    destructive: "350 77% 51%",
    destructiveForeground: "0 0% 100%",
    border: "195 5% 88%",
    input: "195 5% 88%",
    ring: "350 77% 51%",
    chart1: "350 77% 51%",
    chart2: "160 84% 39%",
    chart3: "38 92% 50%",
    chart4: "263 70% 50%",
    chart5: "192 22% 9%",
    sidebar: "0 0% 100%",
    sidebarForeground: "192 22% 9%",
    sidebarPrimary: "350 77% 51%",
    sidebarPrimaryForeground: "0 0% 100%",
    sidebarAccent: "350 77% 96%",
    sidebarAccentForeground: "350 75% 41%",
    sidebarBorder: "195 5% 88%",
    sidebarRing: "350 77% 51%",
  },
  dark: {
    background: "220 14% 7%",
    foreground: "210 20% 96%",
    card: "220 13% 11%",
    cardForeground: "210 20% 96%",
    popover: "220 13% 11%",
    popoverForeground: "210 20% 96%",
    primary: "350 82% 60%",
    primaryForeground: "0 0% 100%",
    secondary: "220 11% 16%",
    secondaryForeground: "210 20% 96%",
    muted: "220 11% 14%",
    mutedForeground: "215 14% 68%",
    accent: "220 11% 16%",
    accentForeground: "210 20% 96%",
    destructive: "350 82% 60%",
    destructiveForeground: "0 0% 100%",
    border: "220 10% 20%",
    input: "220 10% 16%",
    ring: "350 82% 60%",
    chart1: "350 82% 60%",
    chart2: "160 74% 48%",
    chart3: "38 92% 58%",
    chart4: "263 70% 62%",
    chart5: "210 20% 96%",
    sidebar: "220 14% 9%",
    sidebarForeground: "210 20% 96%",
    sidebarPrimary: "350 82% 60%",
    sidebarPrimaryForeground: "0 0% 100%",
    sidebarAccent: "220 11% 16%",
    sidebarAccentForeground: "210 20% 96%",
    sidebarBorder: "220 10% 18%",
    sidebarRing: "350 82% 60%",
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

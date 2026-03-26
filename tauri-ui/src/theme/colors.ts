type TokenSet = Record<string, string>;
type ThemeMode = "light" | "dark";
type DesktopRole = "access" | "tv";
type ThemeColorSet = Record<ThemeMode, TokenSet>;

export const accessThemeColors = {
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

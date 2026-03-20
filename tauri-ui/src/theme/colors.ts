/**
 * Brand color palette — single source of truth.
 * Dark theme inspired by Claude Code's aesthetic:
 * near-black backgrounds, warm orange accent, clean neutrals.
 */

export const lightPalette = {
  brand1: "#264653", // deep teal — primary
  brand2: "#e63946", // teal — secondary / accent
  brand3: "#e9c46a", // golden yellow — highlight
  brand4: "#f4a261", // warm orange — warning
  brand5: "#e76f51", // coral red — destructive
} as const;

export const darkPalette = {
  brand1: "#131418", // near-black — background base
  brand2: "#1c1e24", // dark surface — card / surface
  brand3: "#2a2d36", // muted dark — borders / muted
  brand4: "#8b8fa8", // muted slate — secondary text
  brand5: "#e2e4ec", // off-white — foreground text
} as const;

/**
 * Semantic token map — used in CSS variables.
 * HSL values are derived from the palette above.
 * These are injected into :root and .dark in index.css
 */
export const semanticTokens = {
  light: {
    background:    "210 20% 98%",
    foreground:    "200 30% 17%",
    card:          "0 0% 100%",
    cardForeground:"200 30% 17%",
    popover:       "0 0% 100%",
    popoverForeground: "200 30% 17%",
    primary:       "174 58% 39%",
    primaryForeground: "0 0% 100%",
    secondary:     "42 74% 66%",
    secondaryForeground: "200 30% 17%",
    muted:         "210 15% 93%",
    mutedForeground: "200 10% 45%",
    accent:        "27 88% 67%",
    accentForeground: "200 30% 17%",
    destructive:   "14 76% 61%",
    destructiveForeground: "0 0% 100%",
    border:        "210 15% 88%",
    input:         "210 15% 88%",
    ring:          "174 58% 39%",
    chart1:        "174 58% 39%",
    chart2:        "42 74% 66%",
    chart3:        "27 88% 67%",
    chart4:        "14 76% 61%",
    chart5:        "200 30% 27%",
    sidebar:       "210 15% 96%",
    sidebarForeground: "200 30% 17%",
    sidebarPrimary: "174 58% 39%",
    sidebarPrimaryForeground: "0 0% 100%",
    sidebarAccent: "210 15% 93%",
    sidebarAccentForeground: "200 30% 17%",
    sidebarBorder: "210 15% 88%",
    sidebarRing:   "174 58% 39%",
  },
  dark: {
    // Backgrounds — near-black, Claude Code inspired
    background:    "228 15% 8%",      // #131418 — near-black base
    foreground:    "228 15% 91%",     // #e2e4ec — off-white text
    card:          "228 13% 12%",     // #1c1e24 — dark card surface
    cardForeground:"228 15% 91%",
    popover:       "228 13% 12%",
    popoverForeground: "228 15% 91%",

    // Primary — warm orange (Claude brand accent)
    primary:       "36 95% 53%",      // #f59e0b — amber-orange
    primaryForeground: "228 15% 8%",  // dark text on orange

    // Secondary / muted surfaces
    secondary:     "228 12% 18%",     // #2a2d36 — elevated surface
    secondaryForeground: "228 15% 91%",
    muted:         "228 12% 16%",     // between bg and card
    mutedForeground: "228 10% 55%",   // #8b8fa8 — muted text

    // Accent — same orange
    accent:        "228 12% 18%",
    accentForeground: "228 15% 91%",

    // Destructive — red
    destructive:   "0 72% 51%",
    destructiveForeground: "0 0% 100%",

    // Borders & inputs — subtle
    border:        "228 12% 20%",     // very subtle border
    input:         "228 12% 16%",
    ring:          "36 95% 53%",      // orange focus ring

    // Charts
    chart1:        "36 95% 53%",
    chart2:        "174 60% 41%",
    chart3:        "270 60% 65%",
    chart4:        "0 72% 51%",
    chart5:        "228 15% 91%",

    // Sidebar
    sidebar:       "228 16% 9%",      // slightly darker than bg
    sidebarForeground: "228 15% 91%",
    sidebarPrimary: "36 95% 53%",
    sidebarPrimaryForeground: "228 15% 8%",
    sidebarAccent: "228 12% 16%",
    sidebarAccentForeground: "228 15% 91%",
    sidebarBorder: "228 12% 16%",
    sidebarRing:   "36 95% 53%",
  },
} as const;


type TokenSet = Record<string, string>;

function toCssVarName(tokenKey: string): string {
  return `--${tokenKey.replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`)}`;
}

function toCssBlock(selector: string, tokens: TokenSet): string {
  const lines = Object.entries(tokens).map(([k, v]) => `  ${toCssVarName(k)}: ${v};`);
  return `${selector} {\n${lines.join("\n")}\n}`;
}

/**
 * Injects CSS variables for light/dark theme directly from semanticTokens.
 * This keeps runtime colors in sync with this file (single source of truth).
 */
export function installSemanticTokenStyles(doc: Document = document): void {
  if (!doc || !doc.head) return;

  const styleId = "monclub-semantic-tokens";
  const cssText = [
    toCssBlock(":root", semanticTokens.light as TokenSet),
    toCssBlock(".dark", semanticTokens.dark as TokenSet),
  ].join("\n\n");

  let styleEl = doc.getElementById(styleId) as HTMLStyleElement | null;
  if (!styleEl) {
    styleEl = doc.createElement("style");
    styleEl.id = styleId;
    doc.head.appendChild(styleEl);
  }
  styleEl.textContent = cssText;
}

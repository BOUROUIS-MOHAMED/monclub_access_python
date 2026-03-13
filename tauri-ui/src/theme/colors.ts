/**
 * Brand color palette â€” single source of truth.
 * Change these values to re-skin the entire app.
 *
 * Light: ["#264653","#2a9d8f","#e9c46a","#f4a261","#e76f51"]
 * Dark:  ["#0d1b2a","#1b263b","#415a77","#778da9","#e0e1dd"]
 */

export const lightPalette = {
  brand1: "#264653", // deep teal â€” primary
  brand2: "#e63946", // teal â€” secondary / accent
  brand3: "#e9c46a", // golden yellow â€” highlight
  brand4: "#f4a261", // warm orange â€” warning
  brand5: "#e76f51", // coral red â€” destructive
} as const;

export const darkPalette = {
  brand1: "#0d1b2a", // deepest navy â€” background base
  brand2: "#1b263b", // dark navy â€” card / surface
  brand3: "#415a77", // muted slate â€” borders / muted
  brand4: "#778da9", // blue-gray â€” secondary text
  brand5: "#e0e1dd", // off-white â€” foreground text
} as const;

/**
 * Semantic token map â€” used in CSS variables.
 * HSL values are derived from the hex palette above.
 * These are injected into :root and .dark in index.css
 */
export const semanticTokens = {
  light: {
    background:    "210 20% 98%",     // near-white warm
    foreground:    "200 30% 17%",     // brand1 ~#264653
    card:          "0 0% 100%",       // white
    cardForeground:"200 30% 17%",
    popover:       "0 0% 100%",
    popoverForeground: "200 30% 17%",
    primary:       "174 58% 39%",     // brand2 ~#2a9d8f
    primaryForeground: "0 0% 100%",
    secondary:     "42 74% 66%",      // brand3 ~#e9c46a
    secondaryForeground: "200 30% 17%",
    muted:         "210 15% 93%",
    mutedForeground: "200 10% 45%",
    accent:        "27 88% 67%",      // brand4 ~#f4a261
    accentForeground: "200 30% 17%",
    destructive:   "14 76% 61%",      // brand5 ~#e76f51
    destructiveForeground: "0 0% 100%",
    border:        "210 15% 88%",
    input:         "210 15% 88%",
    ring:          "174 58% 39%",     // primary ring
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
    background:    "213 43% 11%",     // brand1 ~#0d1b2a
    foreground:    "60 3% 87%",       // brand5 ~#e0e1dd
    card:          "214 37% 17%",     // brand2 ~#1b263b
    cardForeground:"60 3% 87%",
    popover:       "214 37% 17%",
    popoverForeground: "60 3% 87%",
    primary:       "174 58% 39%",     // teal accent (same as light primary for brand consistency)
    primaryForeground: "0 0% 100%",
    secondary:     "213 29% 36%",     // brand3 ~#415a77
    secondaryForeground: "60 3% 87%",
    muted:         "213 29% 26%",
    mutedForeground: "213 19% 58%",   // brand4 ~#778da9
    accent:        "213 29% 36%",
    accentForeground: "60 3% 87%",
    destructive:   "14 76% 61%",
    destructiveForeground: "0 0% 100%",
    border:        "213 29% 26%",
    input:         "213 29% 26%",
    ring:          "174 58% 39%",
    chart1:        "174 58% 39%",
    chart2:        "42 74% 66%",
    chart3:        "27 88% 67%",
    chart4:        "14 76% 61%",
    chart5:        "60 3% 87%",
    sidebar:       "214 37% 14%",
    sidebarForeground: "60 3% 87%",
    sidebarPrimary: "174 58% 39%",
    sidebarPrimaryForeground: "0 0% 100%",
    sidebarAccent: "213 29% 26%",
    sidebarAccentForeground: "60 3% 87%",
    sidebarBorder: "213 29% 26%",
    sidebarRing:   "174 58% 39%",
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

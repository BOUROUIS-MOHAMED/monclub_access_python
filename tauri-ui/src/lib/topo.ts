// The Access v3 design lays several full-bleed screens (Connexion, Accès
// restreint, l'écran de verrouillage, la capture d'enrôlement) on the design
// system's `assets/topographic_1.jpg` at 5–6% opacity.
//
// That asset is not in this repo and shipping a JPEG for a 6%-opacity texture
// would add weight for no benefit, so the pattern is generated: concentric
// contour ellipses as an inline SVG data-URI. No network request, no binary,
// and it inherits crisply at any window size.
const TOPO_SVG = (() => {
  const rings: string[] = [];
  const centres: Array<[number, number, number]> = [[210, 230, 1.25], [520, 470, 0.9]];
  for (const [cx, cy, k] of centres) {
    for (let i = 1; i <= 12; i++) {
      const r = i * 26 * k;
      rings.push(
        `<ellipse cx="${cx}" cy="${cy}" rx="${(r * 1.18).toFixed(1)}" ry="${r.toFixed(1)}"` +
        ` transform="rotate(${i * 3 - 14} ${cx} ${cy})"/>`,
      );
    }
  }
  return (
    '<svg xmlns="http://www.w3.org/2000/svg" width="720" height="720" viewBox="0 0 720 720">' +
    '<g fill="none" stroke="currentColor" stroke-width="1.6">' + rings.join("") + "</g></svg>"
  );
})();

/** Ready-to-use CSS `background-image` value. Pair with a low opacity layer. */
export const TOPO_BACKGROUND_IMAGE = `url("data:image/svg+xml,${encodeURIComponent(
  TOPO_SVG.replace(/currentColor/g, "#121A1C"),
)}")`;

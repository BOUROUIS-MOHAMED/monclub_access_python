/**
 * FavoritesOverlayPage — always-on-top floating dock for quick-access favourites.
 *
 * Anchor model
 * ────────────
 *   The overlay can be pinned to 12 anchor points via the `favorites_overlay_anchor`
 *   config key. Four edge families, each with three alignments:
 *     right-{top,center,bottom}   → handle on right edge, panel grows leftward
 *     left-{top,center,bottom}    → handle on left edge,  panel grows rightward
 *     top-{left,center,right}     → handle on top edge,   panel grows downward
 *     bottom-{left,center,right}  → handle on bottom edge, panel grows upward
 *
 *   On mount and on anchor change we invoke Rust commands to reposition and
 *   resize the Tauri window. The web UI mirrors the orientation: handle pill,
 *   chevron direction, and panel slide axis all follow the chosen edge.
 *
 * Animation model
 * ───────────────
 *   panelMounted  → controls whether the panel is in the DOM
 *   panelOpen     → controls the CSS "open" state (translate + opacity)
 *
 *   Open:   invoke(expand, anchor) → setPanelMounted(true) → rAF → setPanelOpen(true)
 *   Close:  setPanelOpen(false) → 270 ms timeout → setPanelMounted(false)
 *                                                → invoke(collapse, anchor)
 *   Mid-collapse re-hover: cancel timer, flip panelOpen back to true — the
 *   CSS transition reverses in place with no DOM flicker.
 */

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { get, post } from "@/api/client";
import { useFavoritePresets } from "@/api/hooks";
import type { FavoriteDoorPresetDto } from "@/api/types";

// ── Anchor ────────────────────────────────────────────────────────────────────
type Anchor =
  | "right-top" | "right-center" | "right-bottom"
  | "left-top"  | "left-center"  | "left-bottom"
  | "top-left"  | "top-center"   | "top-right"
  | "bottom-left" | "bottom-center" | "bottom-right";

type Edge = "right" | "left" | "top" | "bottom";

const VALID_ANCHORS = new Set<string>([
  "right-top","right-center","right-bottom",
  "left-top","left-center","left-bottom",
  "top-left","top-center","top-right",
  "bottom-left","bottom-center","bottom-right",
]);

function normalizeAnchor(value: unknown): Anchor {
  const s = typeof value === "string" ? value.trim().toLowerCase() : "";
  return (VALID_ANCHORS.has(s) ? s : "right-center") as Anchor;
}

function edgeOf(anchor: Anchor): Edge {
  return anchor.split("-")[0] as Edge;
}

// ── Tauri invoke shim ─────────────────────────────────────────────────────────
let _invoke: ((cmd: string, args?: Record<string, unknown>) => Promise<unknown>) | null = null;
async function tauriInvoke(cmd: string, args?: Record<string, unknown>): Promise<void> {
  if (_invoke === null) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      _invoke = invoke;
    } catch {
      _invoke = undefined as unknown as null;
    }
  }
  if (_invoke) {
    try { await _invoke(cmd, args); } catch { /* noop — desktop only */ }
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function favoriteTitle(f: FavoriteDoorPresetDto, fallbackIndex: number): string {
  return f.doorName?.trim() || `Favori ${f.favoriteOrder ?? fallbackIndex}`;
}
function slotBadge(slot: number): string {
  return slot >= 0 && slot <= 9 ? String(slot) : `F${slot - 9}`;
}
function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

type FlashState = { key: string; ok: boolean; msg: string } | null;

// ── Icons ─────────────────────────────────────────────────────────────────────
function StarIcon({ className, size = 15 }: { className?: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" className={className}>
      <path d="M12 2l2.83 5.73 6.32.92-4.57 4.46 1.08 6.3L12 16.45l-5.66 2.96 1.08-6.3L2.85 8.65l6.32-.92L12 2z" />
    </svg>
  );
}
/** Chevron rotated to point along the given axis. */
function ChevronIcon({ direction, className }: { direction: Edge; className?: string }) {
  // Base glyph points LEFT ("<"). Rotate to point in the panel-open direction.
  const rot = direction === "left" ? 180
            : direction === "top"  ? 90
            : direction === "bottom" ? -90
            : 0;
  return (
    <svg
      width="8"
      height="14"
      viewBox="0 0 8 14"
      fill="none"
      className={className}
      style={{ transform: `rotate(${rot}deg)` }}
    >
      <path d="M6 1.5L2 7L6 12.5" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────
export default function FavoritesOverlayPage() {
  const { data: qa, loading, reload } = useFavoritePresets();
  const [flash, setFlash]       = useState<FlashState>(null);
  const [busyKey, setBusyKey]   = useState<string | null>(null);
  const [handleHovered, setHandleHovered] = useState(false);

  // Anchor (live) — reloaded from config on mount and on broadcast.
  // `anchorLoaded` gates the very first paint so we never render with a
  // stale default anchor (which would flash the handle on the wrong edge
  // before /config replies).
  const [anchor, setAnchor] = useState<Anchor>("right-center");
  const [anchorLoaded, setAnchorLoaded] = useState(false);
  const edge = edgeOf(anchor);
  const isVertical = edge === "right" || edge === "left";

  // Two-phase open/close animation
  const [panelMounted, setPanelMounted] = useState(false);
  const [panelOpen,    setPanelOpen]    = useState(false);

  // Manual refresh flag for the in-panel "sync" button.
  const [syncing, setSyncing] = useState(false);

  const [kbIndex, setKbIndex] = useState<number>(-1);

  const collapseTimer = useRef<number | null>(null);
  const unmountTimer  = useRef<number | null>(null);

  // Track the last-applied anchor so `loadAnchor` can bail out when nothing
  // actually changed. Without this, the native `resize` event that fires
  // during a hover-expand would re-trigger loadAnchor → apply(collapsed) →
  // Rust resize back → visible "big → small" flicker.
  const lastAppliedAnchor = useRef<Anchor | null>(null);

  const favorites = qa?.favorites ?? [];

  // ── Transparency enforcement ─────────────────────────────────────────────
  useLayoutEffect(() => {
    const html = document.documentElement;
    const body = document.body;
    const root = document.getElementById("root");
    html.style.background = "transparent";
    body.style.background = "transparent";
    if (root) {
      root.style.background = "transparent";
      root.style.height = "100%";
    }
  }, []);

  // ── Load anchor from /config and apply to window ─────────────────────────
  // IMPORTANT: only invoke Rust when the anchor value CHANGED. Otherwise the
  // resize event fired by an expand would cause us to re-apply "collapsed"
  // mid-hover and shrink the window under the user's mouse.
  const loadAnchor = useCallback(async () => {
    let next: Anchor = "right-center";
    try {
      const res = await get<any>("/config");
      const cfg = res?.config || res || {};
      next = normalizeAnchor(cfg.favorites_overlay_anchor);
    } catch {
      // /config unreachable — keep the default and flag loaded so the UI
      // doesn't stay blank forever.
    }
    setAnchor(next);
    setAnchorLoaded(true);
    if (lastAppliedAnchor.current !== next) {
      lastAppliedAnchor.current = next;
      void tauriInvoke("apply_favorites_overlay_anchor", { anchor: next, expanded: false });
    }
  }, []);

  useEffect(() => {
    void loadAnchor();
  }, [loadAnchor]);

  // When the Config page saves a new anchor, it invokes
  // `apply_favorites_overlay_anchor` which resizes THIS window. A native
  // resize fires → we re-read /config so the UI flips edge.
  //
  // Also reset the panel state whenever the window becomes visible again
  // (tray-reopened). React state survives the hide/show cycle, so a
  // previously-open panel would otherwise render inside a now-collapsed
  // window and flash "big → small".
  useEffect(() => {
    const onResize = () => { void loadAnchor(); };
    const onFocus  = () => { void loadAnchor(); reload(); };
    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        setPanelMounted(false);
        setPanelOpen(false);
        setKbIndex(-1);
        if (collapseTimer.current) { clearTimeout(collapseTimer.current); collapseTimer.current = null; }
        if (unmountTimer.current)  { clearTimeout(unmountTimer.current);  unmountTimer.current  = null; }
        void loadAnchor();
        // Re-fetch favorites: `favorites_overlay_show_all_presets` may have
        // toggled while the overlay was hidden.
        reload();
      }
    };
    window.addEventListener("resize", onResize);
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.removeEventListener("resize", onResize);
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [loadAnchor, reload]);

  // ── Reload favorites when mounted ─────────────────────────────────────────
  useEffect(() => { reload(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Register OS-level shortcuts for every favorite with a `favoriteShortcut`.
  // The Rust side POSTs the door-open request and emits
  // `favorite-shortcut-triggered` when any registered combo fires anywhere.
  //
  // `favorites` is a new array reference every render (derived from qa), so
  // we derive a JSON signature of only the shortcut-relevant fields and key
  // the effect on that. Otherwise the effect re-runs on every mouse-hover
  // render and saturates Tauri's IPC with register/unregister calls — which
  // was making the whole overlay window freeze / not paint.
  const shortcutEntries = useMemo(
    () =>
      favorites
        .filter((f) => typeof f.favoriteShortcut === "string" && f.favoriteShortcut.trim().length > 0)
        .map((f) => ({
          favoriteId:   Number(f.id),
          deviceId:     Number(f.deviceId),
          doorNumber:   Number(f.doorNumber),
          pulseSeconds: Number(f.pulseSeconds),
          doorName:     String(f.doorName ?? ""),
          deviceName:   String(f.deviceName ?? ""),
          shortcut:     String(f.favoriteShortcut ?? ""),
        })),
    [favorites],
  );
  const shortcutKey = useMemo(() => JSON.stringify(shortcutEntries), [shortcutEntries]);

  useEffect(() => {
    if (shortcutEntries.length === 0) {
      void tauriInvoke("unregister_favorite_shortcuts");
      return;
    }
    void tauriInvoke("register_favorite_shortcuts", { shortcuts: shortcutEntries });
    return () => { void tauriInvoke("unregister_favorite_shortcuts"); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shortcutKey]);

  // Refs to doOpen/doClose — assigned below — so the shortcut-toast effect
  // can attach its Tauri listener ONCE on mount without a dependency loop.
  const doOpenRef  = useRef<() => void>(() => {});
  const doCloseRef = useRef<() => void>(() => {});

  // ── Immediate beep on shortcut press ─────────────────────────────────────
  // Fires before the HTTP call so the user gets instant audio confirmation
  // that the key combo was captured, regardless of network/door outcome.
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        unlisten = await listen<{ favoriteId: number; shortcut: string }>(
          "favorite-shortcut-pressed",
          () => {
            try {
              const ctx = new AudioContext();
              const osc = ctx.createOscillator();
              const gain = ctx.createGain();
              osc.connect(gain);
              gain.connect(ctx.destination);
              osc.type = "sine";
              osc.frequency.value = 880;
              gain.gain.setValueAtTime(0.25, ctx.currentTime);
              gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.12);
              osc.start(ctx.currentTime);
              osc.stop(ctx.currentTime + 0.12);
              osc.onended = () => ctx.close();
            } catch { /* AudioContext unavailable */ }
          },
        );
      } catch { /* Non-Tauri environment */ }
    })();
    return () => { if (unlisten) unlisten(); };
  }, []);

  // ── Toast on shortcut capture ─────────────────────────────────────────────
  // Listens for the Rust-emitted event, shows the flash banner, and briefly
  // expands the overlay (if collapsed) so the toast is actually visible.
  // After ~2.2 s it auto-collapses again.
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let autoCollapseTimer: number | null = null;

    (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        unlisten = await listen<{
          favoriteId: number;
          doorName: string;
          deviceName: string;
          shortcut: string;
          ok: boolean;
          error?: string | null;
        }>("favorite-shortcut-triggered", (event) => {
          const p = event.payload;
          const label = p.doorName?.trim() || p.deviceName || `Favori ${p.favoriteId}`;
          setFlash({
            key: `sc-${p.favoriteId}-${Date.now()}`,
            ok: p.ok,
            msg: p.ok ? `⌨ ${p.shortcut} → ${label}` : `${label}: ${p.error ?? "erreur"}`,
          });
          // Briefly expand so the toast is visible when the user triggered
          // the shortcut from another app.
          doOpenRef.current();
          if (autoCollapseTimer) clearTimeout(autoCollapseTimer);
          autoCollapseTimer = window.setTimeout(() => {
            doCloseRef.current();
          }, 2200);
        });
      } catch {
        // Non-Tauri environment (dev preview in browser) — no events here.
      }
    })();

    return () => {
      if (unlisten) unlisten();
      if (autoCollapseTimer) clearTimeout(autoCollapseTimer);
    };
  }, []);

  // ── Auto-clear flash ──────────────────────────────────────────────────────
  useEffect(() => {
    if (!flash) return undefined;
    const t = window.setTimeout(() => setFlash(null), 2600);
    return () => window.clearTimeout(t);
  }, [flash]);

  const prefersReducedMotion = useMemo(() => {
    if (typeof window === "undefined") return false;
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }, []);

  // ── Open ──────────────────────────────────────────────────────────────────
  const doOpen = useCallback(() => {
    if (collapseTimer.current) { clearTimeout(collapseTimer.current); collapseTimer.current = null; }
    if (unmountTimer.current)  { clearTimeout(unmountTimer.current);  unmountTimer.current  = null; }

    if (panelOpen) return;

    void tauriInvoke("expand_favorites_overlay", { anchor });

    if (!panelMounted) {
      setPanelMounted(true);
      setPanelOpen(false);
      requestAnimationFrame(() =>
        requestAnimationFrame(() => setPanelOpen(true))
      );
    } else {
      setPanelOpen(true);
    }
  }, [panelMounted, panelOpen, anchor]);

  // ── Close ─────────────────────────────────────────────────────────────────
  const doClose = useCallback(() => {
    if (unmountTimer.current) clearTimeout(unmountTimer.current);
    setPanelOpen(false);
    setKbIndex(-1);
    // Fire the Rust collapse animation IMMEDIATELY so the window shrink
    // runs in parallel with the CSS panel slide-out — both finish around
    // the same time, eliminating the "snap" at the end of the close.
    void tauriInvoke("collapse_favorites_overlay", { anchor });
    unmountTimer.current = window.setTimeout(() => {
      setPanelMounted(false);
    }, 280);
  }, [anchor]);

  // Keep refs in sync for the shortcut-toast listener registered above.
  doOpenRef.current  = doOpen;
  doCloseRef.current = doClose;

  const handleMouseEnter = useCallback(() => { doOpen(); }, [doOpen]);
  const scheduleCollapse = useCallback(() => {
    if (collapseTimer.current) clearTimeout(collapseTimer.current);
    collapseTimer.current = window.setTimeout(doClose, 180);
  }, [doClose]);
  const handleMouseLeave = useCallback(() => { scheduleCollapse(); }, [scheduleCollapse]);

  // ── Door open ─────────────────────────────────────────────────────────────
  const handleOpen = useCallback(async (fav: FavoriteDoorPresetDto, index: number) => {
    const key = String(fav.id);
    setBusyKey(key);
    try {
      await post(`/devices/${fav.deviceId}/door/open`, {
        doorNumber:   fav.doorNumber,
        pulseSeconds: fav.pulseSeconds,
      });
      setFlash({ key, ok: true, msg: favoriteTitle(fav, index) });
    } catch (err) {
      setFlash({ key, ok: false, msg: String(err) });
    } finally {
      setBusyKey(null);
    }
  }, []);

  // ── Keyboard ──────────────────────────────────────────────────────────────
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!panelMounted) return;
      if (e.key === "Escape") { e.preventDefault(); doClose(); return; }
      if (favorites.length === 0) return;

      if (e.key === "ArrowDown") {
        e.preventDefault();
        setKbIndex(i => clamp(i < 0 ? 0 : i + 1, 0, favorites.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setKbIndex(i => clamp(i < 0 ? 0 : i - 1, 0, favorites.length - 1));
      } else if (e.key === "Enter" && kbIndex >= 0 && kbIndex < favorites.length) {
        e.preventDefault();
        void handleOpen(favorites[kbIndex], kbIndex);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [panelMounted, favorites, kbIndex, doClose, handleOpen]);

  // ── Derived transitions ───────────────────────────────────────────────────
  // Timings mirror the Rust window animation (~260 ms, ease-out-cubic) so
  // the panel reaches its final position at the same moment the window
  // finishes resizing — no residual snap.
  const openDur  = prefersReducedMotion ? 0 : 260;
  const closeDur = prefersReducedMotion ? 0 : 260;

  // Panel hidden-state transform: use a fixed pixel offset larger than the
  // max expanded panel size so the panel stays fully off-screen regardless
  // of the current (animating) window size. Percentage-based offsets would
  // drift as the panel's own width changes with the window.
  const hiddenTransform =
    edge === "right"  ? "translate3d(360px, 0, 0)"
    : edge === "left" ? "translate3d(-360px, 0, 0)"
    : edge === "top"  ? "translate3d(0, -360px, 0)"
    : /* bottom */      "translate3d(0, 360px, 0)";

  // Match ease-out-cubic on open (same curve as Rust) and a gentle
  // ease-in-cubic on close so the slide feels symmetric.
  const panelTransitionStyle: React.CSSProperties = {
    transition: panelOpen
      ? `transform ${openDur}ms cubic-bezier(0.33, 1, 0.68, 1), opacity ${openDur}ms ease-out`
      : `transform ${closeDur}ms cubic-bezier(0.32, 0, 0.67, 0), opacity ${closeDur}ms ease-in`,
    transform: panelOpen ? "translate3d(0, 0, 0)" : hiddenTransform,
    opacity:   panelOpen ? 1 : 0,
    willChange: "transform, opacity",
  };

  // Handle cross-fades with the panel's open state. The panel's background
  // is 86% opaque (so the frosted-blur effect works), which means a
  // fully-opaque handle below would bleed through as a ghost orange strip.
  // Instead we fade the handle out as `panelOpen` goes true, and back in as
  // it goes false — so the pill and the panel effectively swap places.
  // Duration matches the panel slide so neither runs ahead of the other.
  const handleTransitionStyle: React.CSSProperties = {
    transition: "opacity 220ms ease",
    opacity: panelOpen ? 0 : 1,
    transform: "translate3d(0,0,0)",
    pointerEvents: panelOpen ? "none" : "auto",
  };

  // When the panel opens the mouse leaves the handle region → handleHovered
  // flips back to false and the hover animations (scale 1.04, chevron shift,
  // glow, sheen) all spring back to rest at the same time the handle is
  // fading out. Visually that's a "shake". Freeze the hover state to `false`
  // the moment the panel is open so the pill fades out perfectly still.
  const showHoverEffect = handleHovered && !panelOpen;

  // Handle positioning — pill lies along the docked edge.
  const handleContainerStyle: React.CSSProperties = isVertical
    ? { width: 36, top: 0, bottom: 0, [edge]: 0 }
    : { height: 36, left: 0, right: 0, [edge]: 0 };

  // Handle pill inner layout
  const handleFlexDir = isVertical ? "flex-col" : "flex-row";
  const handleRadius =
    edge === "right"  ? "rounded-l-2xl"
    : edge === "left" ? "rounded-r-2xl"
    : edge === "top"  ? "rounded-b-2xl"
    : /* bottom */      "rounded-t-2xl";

  // Hover micro-translation
  const handleHoverShift =
    edge === "right"  ? "translate3d(-2px, 0, 0)"
    : edge === "left" ? "translate3d(2px, 0, 0)"
    : edge === "top"  ? "translate3d(0, 2px, 0)"
    : /* bottom */      "translate3d(0, -2px, 0)";

  // Chevron points toward where the panel will appear (opposite of edge).
  const chevronDir: Edge =
    edge === "right"  ? "left"
    : edge === "left" ? "right"
    : edge === "top"  ? "bottom"
    : /* bottom */      "top";

  // Chevron hover micro-shift matches handle
  const chevronHoverShift =
  
    edge === "right"  ? "translateX(14px)"
    : edge === "left" ? "translateX(2px)"
    : edge === "top"  ? "translateY(2px)"
    : /* bottom */      "translateY(-2px)";

  // Glow direction — cast away from the handle into the screen
  const glowShadow =
    edge === "right"  ? "-4px 0 24px 5px hsl(var(--primary) / 0.5)"
    : edge === "left" ? "4px 0 24px 5px hsl(var(--primary) / 0.5)"
    : edge === "top"  ? "0 4px 24px 5px hsl(var(--primary) / 0.5)"
    : /* bottom */      "0 -4px 24px 5px hsl(var(--primary) / 0.5)";

  // Base gradient direction (from edge face outward)
  const pillGradient =
    edge === "right"
      ? "linear-gradient(168deg, hsl(var(--primary)) 0%, hsl(var(--primary)) 45%, hsl(var(--primary) / 0.82) 100%)"
      : edge === "left"
        ? "linear-gradient(-168deg, hsl(var(--primary)) 0%, hsl(var(--primary)) 45%, hsl(var(--primary) / 0.82) 100%)"
      : edge === "top"
        ? "linear-gradient(258deg, hsl(var(--primary)) 0%, hsl(var(--primary)) 45%, hsl(var(--primary) / 0.82) 100%)"
        : "linear-gradient(78deg, hsl(var(--primary)) 0%, hsl(var(--primary)) 45%, hsl(var(--primary) / 0.82) 100%)";

  // Panel border-radius — rounded on the side facing away from the edge.
  const panelRadius =
    edge === "right"  ? "20px 0 0 20px"
    : edge === "left" ? "0 20px 20px 0"
    : edge === "top"  ? "0 0 20px 20px"
    : /* bottom */      "20px 20px 0 0";

  // Accent stripe position on the panel (along the docked edge inside)
  const accentStripeStyle: React.CSSProperties = isVertical
    ? { height: 3, width: "100%", background:
        "linear-gradient(90deg, hsl(var(--primary)) 0%, hsl(var(--primary)/0.45) 75%, transparent 100%)",
        borderRadius: edge === "right" ? "20px 0 0 0" : "0 20px 0 0" }
    : { width: 3, height: "100%", background:
        "linear-gradient(180deg, hsl(var(--primary)) 0%, hsl(var(--primary)/0.45) 75%, transparent 100%)",
        borderRadius: edge === "top" ? "0 0 0 20px" : "0 20px 0 0" };

  // ────────────────────────────────────────────────────────────────────────────
  return (
    <>
      <style>{`
        html, body, #root {
          background: transparent !important;
          background-color: transparent !important;
          margin: 0;
          padding: 0;
        }
        html, body { height: 100%; }
        *::selection { background: hsl(var(--primary)/0.25); }
      `}</style>

      <div
        className="h-screen w-screen overflow-hidden bg-transparent"
        onMouseEnter={anchorLoaded ? handleMouseEnter : undefined}
        onMouseLeave={anchorLoaded ? handleMouseLeave : undefined}
      >

      {/* Gate first paint on the anchor so we never render the handle on
          the wrong edge before /config replies. The window itself is
          already sized correctly by Rust at this point. */}
      {anchorLoaded && <>

        {/* ── Collapsed handle ──────────────────────────────────────────────
            `z-0` establishes a stacking context so the `z-10` used on
            chevrons/dots inside the pill stays CONTAINED to the handle.
            Without it those inner elements would bleed above the expanded
            panel — you'd see the orange edge and the arrow tip poking
            through while the panel is open. */}
        <div
          className="absolute cursor-pointer select-none z-0"
          style={{ ...handleContainerStyle, ...handleTransitionStyle }}
          onMouseEnter={() => setHandleHovered(true)}
          onMouseLeave={() => setHandleHovered(false)}
        >
          {/* Coloured glow */}
          <div
            aria-hidden
            className={`pointer-events-none absolute ${handleRadius}`}
            style={{
              inset: 0,
              opacity: showHoverEffect ? 1 : 0,
              transition: "opacity 220ms ease",
              boxShadow: glowShadow,
              willChange: "opacity",
            }}
          />

          {/* Main pill */}
          <div
            className={`relative flex ${handleFlexDir} items-center justify-between ${handleRadius} ${isVertical ? "h-full w-full px-1 py-2.5" : "h-full w-full px-2.5 py-1"}`}
            style={{
              transform: showHoverEffect ? `${handleHoverShift} scale(1.04)` : "translate3d(0,0,0) scale(1)",
              transition: "transform 200ms cubic-bezier(0.22, 0.9, 0.28, 1)",
              background: pillGradient,
              // Inset-only shadows: an outset shadow on a 36px-wide window
              // renders outside the window bounds and on Windows' DWM shows
              // up as a faint dark rectangle next to the pill — exactly the
              // "second background" symptom.
              boxShadow:
                "inset 0 1px 0 rgba(255,255,255,0.26), " +
                "inset -1px 0 0 rgba(0,0,0,0.1)",
              willChange: "transform",
              backfaceVisibility: "hidden",
            }}
          >
            {/* Sheen */}
            <div
              aria-hidden
              className={`pointer-events-none absolute inset-0 ${handleRadius}`}
              style={{
                background: isVertical
                  ? "linear-gradient(180deg, rgba(255,255,255,0.22) 0%, rgba(255,255,255,0) 55%)"
                  : "linear-gradient(90deg, rgba(255,255,255,0.22) 0%, rgba(255,255,255,0) 55%)",
                opacity: showHoverEffect ? 1 : 0,
                transition: "opacity 180ms ease",
              }}
            />

            {/* First chevron */}
            <div
              className="relative z-10"
              style={{
                transition: "transform 200ms cubic-bezier(0.4, 0, 0.2, 1)",
                transform: showHoverEffect ? chevronHoverShift : "translate3d(0,0,0)",
                willChange: "transform",
              }}
            >
              <ChevronIcon direction={chevronDir} className="text-primary-foreground/90" />
            </div>

            {/* Middle grab-bar dots */}
            <div className={`relative z-10 flex ${isVertical ? "flex-col" : "flex-row"} gap-1`}>
              <div className="h-[3px] w-[3px] rounded-full bg-primary-foreground/45" />
              <div className="h-[3px] w-[3px] rounded-full bg-primary-foreground/45" />
              <div className="h-[3px] w-[3px] rounded-full bg-primary-foreground/45" />
            </div>

            {/* Second chevron */}
            <div
              className="relative z-10"
              style={{
                transition: "transform 200ms cubic-bezier(0.4, 0, 0.2, 1)",
                transform: showHoverEffect ? chevronHoverShift : "translate3d(0,0,0)",
                willChange: "transform",
              }}
            >
              <ChevronIcon direction={chevronDir} className="text-primary-foreground/90" />
            </div>
          </div>
        </div>

        {/* ── Expanded panel ────────────────────────────────────────────── */}
        {panelMounted && (
          <div className="absolute inset-0 z-10" style={panelTransitionStyle}>
            <div
              className="flex h-full w-full flex-col overflow-hidden"
              style={{
                borderRadius: panelRadius,
                background: "hsl(var(--background) / 0.86)",
                backdropFilter: "blur(16px) saturate(1.3)",
                WebkitBackdropFilter: "blur(16px) saturate(1.3)",
                border: "1px solid hsl(var(--border) / 0.5)",
                boxShadow:
                  "-14px 0 48px rgba(0,0,0,0.32), " +
                  "-3px 0 10px rgba(0,0,0,0.12), " +
                  "inset 1px 0 0 hsl(var(--foreground) / 0.04)",
              }}
            >
              {/* Top accent */}
              <div className="shrink-0" style={accentStripeStyle} />

              {/* Header */}
              <div className="flex shrink-0 items-center justify-between border-b border-border/40 px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <div
                    className="flex h-5 w-5 items-center justify-center rounded-md"
                    style={{ background: "hsl(var(--primary) / 0.14)" }}
                  >
                    <StarIcon className="text-primary" size={11} />
                  </div>
                  <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-primary">
                    Accès rapide
                  </span>
                </div>
                <div className="flex items-center gap-1">
                  {/* Manual sync — refetches from the remote server so new
                      dashboard favorites appear without waiting for auto-sync. */}
                  <button
                    type="button"
                    disabled={syncing}
                    className="flex h-6 w-6 items-center justify-center rounded-full text-muted-foreground/60
                               transition-all duration-150 hover:bg-muted hover:text-foreground
                               focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/50
                               disabled:opacity-50"
                    onClick={async () => {
                      if (syncing) return;
                      setSyncing(true);
                      try {
                        // `forceDeviceRefresh` strips the devicesVersion token
                        // on the client so the server must re-send full device
                        // state (including preset favoriteEnabled changes —
                        // those don't bump the backend's devicesVersion).
                        await post("/sync/now", {
                          entityType: "FAVORITE",
                          forceDeviceRefresh: true,
                          reason: "user_manual_favorites_refresh",
                        });
                        // Give the backend a moment to populate, then reload.
                        window.setTimeout(() => { reload(); setSyncing(false); }, 2000);
                      } catch (e) {
                        setFlash({ key: "sync", ok: false, msg: String(e) });
                        setSyncing(false);
                      }
                    }}
                    aria-label="Synchroniser les favoris"
                    title="Synchroniser les favoris depuis le serveur"
                  >
                    <svg
                      width="11" height="11" viewBox="0 0 12 12" fill="none"
                      className={syncing ? "animate-spin" : ""}
                    >
                      <path d="M10.5 6a4.5 4.5 0 1 1-1.32-3.18M10.5 1.5V4.5H7.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </button>
                  <button
                    type="button"
                    className="flex h-6 w-6 items-center justify-center rounded-full text-muted-foreground/60
                               transition-all duration-150 hover:rotate-90 hover:bg-muted hover:text-foreground
                               focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/50"
                    onClick={doClose}
                    aria-label="Réduire le panneau favoris"
                  >
                    <svg width="9" height="9" viewBox="0 0 10 10" fill="none">
                      <path d="M2 2L8 8M8 2L2 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
                    </svg>
                  </button>
                </div>
              </div>

              {/* Flash banner */}
              {flash && (
                <div
                  className={[
                    "mx-3 mt-2.5 shrink-0 flex items-center gap-2 rounded-xl px-3 py-2 text-xs font-medium",
                    "animate-in fade-in slide-in-from-top-1 duration-200",
                    flash.ok
                      ? "bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/25"
                      : "bg-destructive/15 text-destructive ring-1 ring-destructive/25",
                  ].join(" ")}
                >
                  {flash.ok ? (
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none" className="shrink-0">
                      <circle cx="6" cy="6" r="5.5" stroke="currentColor" strokeOpacity="0.5" />
                      <path d="M3.5 6L5.2 7.7L8.5 4.3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  ) : (
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none" className="shrink-0">
                      <circle cx="6" cy="6" r="5.5" stroke="currentColor" strokeOpacity="0.5" />
                      <path d="M4 4L8 8M8 4L4 8" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
                    </svg>
                  )}
                  <span className="truncate">{flash.msg}</span>
                </div>
              )}

              {/* List — single column for vertical panel (right/left anchor);
                  two-column grid for horizontal panel (top/bottom anchor)
                  so items use the extra width instead of leaving large
                  empty bands next to each row. */}
              <div
                className={[
                  "flex-1 overflow-y-auto overflow-x-hidden px-2.5 pb-3 pt-2.5",
                  isVertical ? "space-y-1" : "grid grid-cols-2 gap-1.5 content-start",
                ].join(" ")}
              >

                {loading && favorites.length === 0 && (
                  <div className={isVertical ? "space-y-1.5 px-0.5" : "contents"}>
                    {Array.from({ length: 4 }).map((_, i) => (
                      <div
                        key={i}
                        className="h-[52px] animate-pulse rounded-2xl bg-muted/40"
                        style={{ opacity: 1 - i * 0.2, animationDelay: `${i * 80}ms` }}
                      />
                    ))}
                  </div>
                )}

                {!loading && favorites.length === 0 && (
                  <div
                    className={[
                      "flex flex-col items-center justify-center gap-3 rounded-2xl border border-dashed border-border bg-muted/20 py-8 px-4 text-center",
                      !isVertical && "col-span-2",
                    ].filter(Boolean).join(" ")}
                    style={{
                      opacity: panelOpen ? 1 : 0,
                      transform: panelOpen ? "translateY(0)" : "translateY(6px)",
                      transition: "opacity 280ms ease-out 80ms, transform 280ms cubic-bezier(0.22,0.9,0.28,1) 80ms",
                    }}
                  >
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-muted/50">
                      <StarIcon className="text-muted-foreground/50" />
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Aucun favori synchronisé.
                      <br />
                      <span className="text-muted-foreground/60">
                        Marquez des presets depuis le dashboard.
                      </span>
                    </p>
                  </div>
                )}

                {favorites.map((fav, i) => {
                  const key    = String(fav.id);
                  const busy   = busyKey === key;
                  const didFlash = flash?.key === key;
                  const isOk   = didFlash && flash?.ok;
                  const isErr  = didFlash && !flash?.ok;
                  const isKb   = kbIndex === i;

                  const delay = panelOpen ? Math.min(i * 22, 200) : 0;

                  return (
                    <button
                      key={key}
                      type="button"
                      disabled={busy}
                      onClick={() => void handleOpen(fav, i)}
                      onMouseEnter={() => setKbIndex(i)}
                      className={[
                        "group relative flex w-full items-center gap-3 rounded-2xl border px-3 py-2.5",
                        "text-left transition-[background,border-color,transform,box-shadow] duration-150",
                        "disabled:opacity-50 focus:outline-none",
                        isOk
                          ? "border-emerald-500/35 bg-emerald-500/10"
                          : isErr
                            ? "border-destructive/35 bg-destructive/10"
                            : isKb
                              ? "border-primary/45 bg-primary/8 shadow-[0_0_0_1px_hsl(var(--primary)/0.2)]"
                              : "border-border/50 bg-card/60 hover:border-primary/30 hover:bg-primary/5",
                        "active:scale-[0.98]",
                      ].join(" ")}
                      style={{
                        opacity:   panelOpen ? 1 : 0,
                        transform: panelOpen ? "translateY(0)" : "translateY(8px)",
                        transition: [
                          `opacity 240ms ease-out ${delay}ms`,
                          `transform 300ms cubic-bezier(0.22, 0.9, 0.28, 1) ${delay}ms`,
                          `background-color 140ms ease`,
                          `border-color 140ms ease`,
                          `box-shadow 140ms ease`,
                        ].join(", "),
                        willChange: panelOpen ? "auto" : "opacity, transform",
                      }}
                    >
                      <span
                        className={[
                          "flex h-9 w-9 shrink-0 items-center justify-center rounded-xl text-[11px] font-bold",
                          "transition-all duration-200",
                          isOk
                            ? "bg-emerald-500/22 text-emerald-400 scale-110"
                            : isErr
                              ? "bg-destructive/22 text-destructive scale-105"
                              : "bg-primary/12 text-primary group-hover:bg-primary/20 group-hover:scale-105",
                        ].join(" ")}
                      >
                        {slotBadge(fav.favoriteOrder ?? i)}
                      </span>

                      <div className="min-w-0 flex-1">
                        <div className="truncate text-[13px] font-semibold leading-tight text-foreground">
                          {favoriteTitle(fav, i)}
                        </div>
                        <div className="mt-0.5 flex items-center gap-1 text-[10px] text-muted-foreground">
                          <span className="truncate">{fav.deviceName || "Appareil"}</span>
                          <span className="opacity-40">·</span>
                          <span className="shrink-0">{fav.pulseSeconds}s</span>
                        </div>
                      </div>

                      <span className="flex h-4 w-4 shrink-0 items-center justify-center">
                        {busy && (
                          <svg className="h-4 w-4 animate-spin text-primary" viewBox="0 0 24 24" fill="none">
                            <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" opacity="0.2" />
                            <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
                          </svg>
                        )}
                        {!busy && isOk && (
                          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-emerald-400">
                            <path d="M3 7L5.8 9.8L11 4.2" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                          </svg>
                        )}
                        {!busy && isErr && (
                          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-destructive">
                            <path d="M4 4L10 10M10 4L4 10" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
                          </svg>
                        )}
                        {!busy && !didFlash && (
                          <svg
                            width="12"
                            height="12"
                            viewBox="0 0 12 12"
                            fill="none"
                            className={[
                              "transition-all duration-200",
                              isKb
                                ? "text-primary translate-x-0.5"
                                : "text-transparent group-hover:text-primary/55 group-hover:translate-x-0.5",
                            ].join(" ")}
                          >
                            <path d="M2 6H10M7 3L10 6L7 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                          </svg>
                        )}
                      </span>
                    </button>
                  );
                })}
              </div>

              {/* Footer */}
              {!loading && favorites.length > 0 && (
                <div className="shrink-0 border-t border-border/30 px-4 py-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[9px] font-medium uppercase tracking-[0.15em] text-muted-foreground/45">
                      {favorites.length} favori{favorites.length > 1 ? "s" : ""}
                    </span>
                    <span className="text-[9px] text-muted-foreground/35">
                      <kbd className="rounded border border-border/40 bg-muted/30 px-1 font-mono">Esc</kbd>
                      <span className="ml-1">fermer</span>
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </>}
      </div>
    </>
  );
}

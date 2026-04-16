/**
 * FavoritesOverlayPage — always-on-top floating dock for quick-access favourites.
 *
 * Animation model
 * ───────────────
 *   panelMounted  → controls whether the panel is in the DOM
 *   panelOpen     → controls the CSS "open" state (translateX, opacity)
 *
 *   Open:   tauriInvoke(expand) → setPanelMounted(true) → rAF → setPanelOpen(true)
 *   Close:  setPanelOpen(false) → 270 ms timeout → setPanelMounted(false)
 *                                                → tauriInvoke(collapse)
 *   Mid-collapse re-hover: cancel timer, flip panelOpen back to true — the
 *   CSS transition reverses in place with no DOM flicker.
 *
 * Visual design
 * ─────────────
 *   • Collapsed handle: pill-shaped tab docked to the right edge with
 *     gradient primary fill, star glyph, vertical label, chevron hint.
 *   • Expanded panel: translucent frosted-glass surface
 *     (backdrop-filter: blur + saturate) so the desktop is visible behind.
 *   • List items stagger-animate in (opacity+translateY with per-item delay)
 *     so opening feels "alive" rather than a single block reveal.
 *   • Pressing ESC closes the panel; Arrow keys + Enter navigate and fire
 *     favourites when the panel is open.
 */

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { post } from "@/api/client";
import { useQuickAccessState } from "@/api/hooks";
import type { QuickAccessFavoriteDto } from "@/api/types";

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
  if (_invoke) await _invoke(cmd, args);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function favoriteTitle(f: QuickAccessFavoriteDto): string {
  return f.favoriteLabel?.trim() || f.doorName || `Favori ${f.favoriteSlot}`;
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
function ChevronLeftIcon({ className }: { className?: string }) {
  return (
    <svg width="8" height="14" viewBox="0 0 8 14" fill="none" className={className}>
      <path d="M6 1.5L2 7L6 12.5" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────
export default function FavoritesOverlayPage() {
  const { data: qa, loading, reload } = useQuickAccessState();
  const [flash, setFlash]       = useState<FlashState>(null);
  const [busyKey, setBusyKey]   = useState<string | null>(null);
  const [handleHovered, setHandleHovered] = useState(false);

  // Two-phase open/close animation
  const [panelMounted, setPanelMounted] = useState(false);
  const [panelOpen,    setPanelOpen]    = useState(false);

  // Keyboard-driven selection (independent of DOM focus so mouse users
  // never see a stale focus ring)
  const [kbIndex, setKbIndex] = useState<number>(-1);

  const collapseTimer = useRef<number | null>(null);
  const unmountTimer  = useRef<number | null>(null);

  const favorites = qa?.favorites ?? [];

  // ── Document-level transparency ───────────────────────────────────────────
  // Tauri creates this window with transparent(true); Tailwind base would
  // paint bg-background on <body> — neutralise that so the desktop shows
  // through during the resize animation.
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

  // ── Reload when mounted ───────────────────────────────────────────────────
  useEffect(() => { reload(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Auto-clear flash ──────────────────────────────────────────────────────
  useEffect(() => {
    if (!flash) return undefined;
    const t = window.setTimeout(() => setFlash(null), 2600);
    return () => window.clearTimeout(t);
  }, [flash]);

  // ── Respect prefers-reduced-motion ────────────────────────────────────────
  const prefersReducedMotion = useMemo(() => {
    if (typeof window === "undefined") return false;
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }, []);

  // ── Open ──────────────────────────────────────────────────────────────────
  const doOpen = useCallback(() => {
    if (collapseTimer.current) { clearTimeout(collapseTimer.current); collapseTimer.current = null; }
    if (unmountTimer.current)  { clearTimeout(unmountTimer.current);  unmountTimer.current  = null; }

    if (panelOpen) return;

    // Resize window first so the canvas is ready by the time we render
    void tauriInvoke("expand_favorites_overlay");

    if (!panelMounted) {
      setPanelMounted(true);
      setPanelOpen(false);
      requestAnimationFrame(() =>
        requestAnimationFrame(() => setPanelOpen(true))
      );
    } else {
      // Mid-collapse: reverse the CSS animation
      setPanelOpen(true);
    }
  }, [panelMounted, panelOpen]);

  // ── Close ─────────────────────────────────────────────────────────────────
  const doClose = useCallback(() => {
    if (unmountTimer.current) clearTimeout(unmountTimer.current);
    setPanelOpen(false);
    setKbIndex(-1);
    unmountTimer.current = window.setTimeout(() => {
      setPanelMounted(false);
      void tauriInvoke("collapse_favorites_overlay");
    }, 270);
  }, []);

  // ── Mouse hover ───────────────────────────────────────────────────────────
  const handleMouseEnter = useCallback(() => { doOpen(); }, [doOpen]);
  const scheduleCollapse = useCallback(() => {
    if (collapseTimer.current) clearTimeout(collapseTimer.current);
    collapseTimer.current = window.setTimeout(doClose, 180);
  }, [doClose]);
  const handleMouseLeave = useCallback(() => { scheduleCollapse(); }, [scheduleCollapse]);

  // ── Door open ─────────────────────────────────────────────────────────────
  const handleOpen = useCallback(async (fav: QuickAccessFavoriteDto) => {
    const key = `${fav.favoriteSlot}:${fav.presetId}`;
    setBusyKey(key);
    try {
      await post(`/devices/${fav.deviceId}/door/open`, {
        doorNumber:   fav.doorNumber,
        pulseSeconds: fav.pulseSeconds,
      });
      setFlash({ key, ok: true, msg: favoriteTitle(fav) });
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
        void handleOpen(favorites[kbIndex]);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [panelMounted, favorites, kbIndex, doClose, handleOpen]);

  // ── Derived transitions ───────────────────────────────────────────────────
  const openDur  = prefersReducedMotion ? 0 : 320;
  const closeDur = prefersReducedMotion ? 0 : 220;

  const panelTransitionStyle: React.CSSProperties = {
    transition: panelOpen
      ? `transform ${openDur}ms cubic-bezier(0.22, 0.9, 0.28, 1), opacity 220ms ease-out`
      : `transform ${closeDur}ms cubic-bezier(0.4, 0, 1, 1), opacity 160ms ease-in`,
    transform: panelOpen ? "translateX(0)" : "translateX(calc(100% + 16px))",
    opacity:   panelOpen ? 1 : 0,
    willChange: "transform, opacity",
  };

  const handleVisible = !panelMounted;
  // Handle fills the full window height via `inset-y-0`, so we do NOT need
  // any Y translation for vertical centring.  Only translateX for the
  // hide animation.
  const handleTransitionStyle: React.CSSProperties = {
    transition: "opacity 180ms ease, transform 220ms cubic-bezier(0.4, 0, 0.2, 1)",
    opacity:       handleVisible ? 1 : 0,
    transform:     handleVisible ? "translateX(0)" : "translateX(14px)",
    pointerEvents: handleVisible ? "auto" : "none",
  };

  // ────────────────────────────────────────────────────────────────────────────
  return (
    <>
      {/* Window-wide transparency enforcement — applied during the first
          render so the dark body bg never paints. */}
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
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
      >

        {/* ── Collapsed handle ──────────────────────────────────────────────
            Fills the full window height via `inset-y-0`, so it looks right
            no matter what Tauri sized the window to.  Uses a classic drawer
            grab-bar design: star at the top, three dots in the middle,
            chevron at the bottom.
            Performance: base gradient + shadow are STATIC. Hover polish is
            all opacity-fade overlays and transforms — GPU-only. */}
        <div
          className="absolute inset-y-0 right-0 cursor-pointer select-none"
          style={{ width: 36, ...handleTransitionStyle }}
          onMouseEnter={() => setHandleHovered(true)}
          onMouseLeave={() => setHandleHovered(false)}
        >
          {/* Coloured glow */}
          <div
            aria-hidden
            className="pointer-events-none absolute rounded-l-2xl"
            style={{
              inset: 0,
              opacity: handleHovered ? 1 : 0,
              transition: "opacity 220ms ease",
              boxShadow: "-4px 0 24px 5px hsl(var(--primary) / 0.5)",
              willChange: "opacity",
            }}
          />

          {/* Main pill — fills the window vertically */}
          <div
            className="relative flex h-full flex-col items-center justify-between rounded-l-2xl px-1 py-2.5"
            style={{
              width: 36,
              transform: handleHovered
                ? "translate3d(-2px, 0, 0) scale(1.04)"
                : "translate3d(0, 0, 0) scale(1)",
              transition: "transform 200ms cubic-bezier(0.22, 0.9, 0.28, 1)",
              background:
                "linear-gradient(168deg, hsl(var(--primary)) 0%, hsl(var(--primary)) 45%, hsl(var(--primary) / 0.82) 100%)",
              boxShadow:
                "-4px 2px 18px rgba(0,0,0,0.46), " +
                "inset 0 1px 0 rgba(255,255,255,0.26), " +
                "inset -1px 0 0 rgba(0,0,0,0.1)",
              willChange: "transform",
              backfaceVisibility: "hidden",
            }}
          >
            {/* Top sheen */}
            <div
              aria-hidden
              className="pointer-events-none absolute inset-0 rounded-l-2xl"
              style={{
                background:
                  "linear-gradient(180deg, rgba(255,255,255,0.22) 0%, rgba(255,255,255,0) 55%)",
                opacity: handleHovered ? 1 : 0,
                transition: "opacity 180ms ease",
              }}
            />

            {/* Thin top highlight line */}
            <div
              aria-hidden
              className="absolute left-0 right-0 top-0 h-px rounded-tl-2xl"
              style={{ background: "rgba(255,255,255,0.32)" }}
            />

            
            {/* Chevron */}
            <div
              className="relative z-10"
              style={{
                transition: "transform 200ms cubic-bezier(0.4, 0, 0.2, 1)",
                transform: handleHovered ? "translateX(-2px)" : "translateX(0)",
                willChange: "transform",
              }}
            >
              <ChevronLeftIcon className="text-primary-foreground/90" />
            </div>
            {/* Middle — three decorative dots (grab-bar style) */}
            <div className="relative z-10 flex flex-col gap-1">
              <div className="h-[3px] w-[3px] rounded-full bg-primary-foreground/45" />
              <div className="h-[3px] w-[3px] rounded-full bg-primary-foreground/45" />
              <div className="h-[3px] w-[3px] rounded-full bg-primary-foreground/45" />
            </div>

            {/* Chevron */}
            <div
              className="relative z-10"
              style={{
                transition: "transform 200ms cubic-bezier(0.4, 0, 0.2, 1)",
                transform: handleHovered ? "translateX(-2px)" : "translateX(0)",
                willChange: "transform",
              }}
            >
              <ChevronLeftIcon className="text-primary-foreground/90" />
            </div>
          </div>
        </div>

        {/* ── Expanded panel ────────────────────────────────────────────── */}
        {panelMounted && (
          <div className="absolute inset-0" style={panelTransitionStyle}>
            <div
              className="flex h-full flex-col overflow-hidden"
              style={{
                borderRadius: "20px 0 0 20px",
                // Frosted glass: translucent + moderate blur.
                // blur() above ~20px kills framerate on weaker GPUs; 16px is
                // still convincingly glassy without the jank.
                background: "hsl(var(--background) / 0.86)",
                backdropFilter: "blur(16px) saturate(1.3)",
                WebkitBackdropFilter: "blur(16px) saturate(1.3)",
                border: "1px solid hsl(var(--border) / 0.5)",
                borderRight: "none",
                boxShadow:
                  "-14px 0 48px rgba(0,0,0,0.32), " +
                  "-3px 0 10px rgba(0,0,0,0.12), " +
                  "inset 1px 0 0 hsl(var(--foreground) / 0.04)",
              }}
            >
              {/* Top accent stripe */}
              <div
                className="h-[3px] shrink-0"
                style={{
                  background:
                    "linear-gradient(90deg, hsl(var(--primary)) 0%, hsl(var(--primary)/0.45) 75%, transparent 100%)",
                  borderRadius: "20px 0 0 0",
                }}
              />

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

              {/* List */}
              <div className="flex-1 overflow-y-auto overflow-x-hidden px-2.5 pb-3 pt-2.5 space-y-1">

                {/* Skeleton */}
                {loading && favorites.length === 0 && (
                  <div className="space-y-1.5 px-0.5">
                    {Array.from({ length: 4 }).map((_, i) => (
                      <div
                        key={i}
                        className="h-[52px] animate-pulse rounded-2xl bg-muted/40"
                        style={{
                          opacity: 1 - i * 0.2,
                          animationDelay: `${i * 80}ms`,
                        }}
                      />
                    ))}
                  </div>
                )}

                {/* Empty */}
                {!loading && favorites.length === 0 && (
                  <div
                    className="flex flex-col items-center justify-center gap-3 rounded-2xl border border-dashed border-border bg-muted/20 py-8 px-4 text-center"
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

                {/* Items — stagger-in on panel open */}
                {favorites.map((fav, i) => {
                  const key    = `${fav.favoriteSlot}:${fav.presetId}`;
                  const busy   = busyKey === key;
                  const didFlash = flash?.key === key;
                  const isOk   = didFlash && flash?.ok;
                  const isErr  = didFlash && !flash?.ok;
                  const isKb   = kbIndex === i;

                  // Stagger: each card appears ~22 ms after the previous,
                  // capped at 200 ms so long lists don't drag.
                  const delay = panelOpen ? Math.min(i * 22, 200) : 0;

                  return (
                    <button
                      key={key}
                      type="button"
                      disabled={busy}
                      onClick={() => void handleOpen(fav)}
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
                        // Stagger entrance (GPU-only: opacity + transform).
                        // Hover effects on bg/border use Tailwind-provided
                        // transitions which are separate from this rule.
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
                      {/* Slot badge */}
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
                        {slotBadge(fav.favoriteSlot)}
                      </span>

                      {/* Label */}
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-[13px] font-semibold leading-tight text-foreground">
                          {favoriteTitle(fav)}
                        </div>
                        <div className="mt-0.5 flex items-center gap-1 text-[10px] text-muted-foreground">
                          <span className="truncate">{fav.deviceName || "Appareil"}</span>
                          <span className="opacity-40">·</span>
                          <span className="shrink-0">{fav.pulseSeconds}s</span>
                        </div>
                      </div>

                      {/* Trailing icon slot */}
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
      </div>
    </>
  );
}

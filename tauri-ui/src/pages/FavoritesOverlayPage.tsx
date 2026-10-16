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
import { doorRequestedMessage } from "@/api/realtime";
import { INK, SOFT, type Tone } from "@/components/ui/tone";
import {
  Check,
  CircleAlert,
  CircleCheck,
  CircleX,
  LockOpen,
  RefreshCw,
  Send,
  X,
  type LucideIcon,
} from "lucide-react";

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

// Flash tones: success = the controller accepted the open; info = filed for the
// PC pilote (its result is not visible here); warning = filed but the PC pilote is
// offline, so it will expire; error = refused or failed.
type FlashTone = Extract<Tone, "success" | "info" | "warning" | "error">;
type FlashState = { key: string; tone: FlashTone; msg: string } | null;

const FLASH_ICON: Record<FlashTone, LucideIcon> = {
  success: CircleCheck, info: Send, warning: CircleAlert, error: CircleX,
};
const FLASH_END_ICON: Record<FlashTone, LucideIcon> = {
  success: Check, info: Send, warning: CircleAlert, error: X,
};
const ITEM_HIT: Record<FlashTone, string> = {
  success: "border-success/45 bg-success/8",
  info: "border-info/45 bg-info/8",
  warning: "border-warning/45 bg-warning/8",
  error: "border-error/45 bg-error/8",
};
const KBD = "rounded border border-grey/40 bg-muted px-1 font-mono";

// The Rust shortcut handler (src-tauri/src/lib.rs, `favorite-shortcut-triggered`)
// reports a door request filed for the PC pilote as ok=false with one of these two
// texts. They are not failures: map them to info / warning here. If the Rust text
// changes, these fall back to the red error flash.
const RUST_REQUEST_SENT = "demandé au PC pilote (résultat non visible ici)";
const RUST_REQUEST_DRIVER_OFFLINE = "PC pilote non connecté : la demande expirera sans ouvrir";

function lowerFirst(text: string): string {
  return text ? text.charAt(0).toLowerCase() + text.slice(1) : text;
}

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
        // Same beep plays for both door shortcuts and the SCR100 scan shortcut.
        unlisten = await listen<{ favoriteId?: number; shortcut: string }>(
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
          // Keyed on the favourite so its row lights up like a click would.
          const key = String(p.favoriteId);
          if (p.ok) {
            setFlash({ key, tone: "success", msg: `${p.shortcut} → ${label} : porte ouverte` });
          } else if (p.error === RUST_REQUEST_SENT) {
            setFlash({ key, tone: "info", msg: `${p.shortcut} → ${label} : demande envoyée au PC pilote. Son résultat n'est pas visible ici.` });
          } else if (p.error === RUST_REQUEST_DRIVER_OFFLINE) {
            setFlash({ key, tone: "warning", msg: `${p.shortcut} → ${label} : demande enregistrée, mais le PC pilote n'est pas connecté : elle expirera sans ouvrir.` });
          } else {
            setFlash({ key, tone: "error", msg: `${p.shortcut} → ${label} : ${p.error ?? "erreur"}` });
          }
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

  // ── Toast on SCR100 scan shortcut result ─────────────────────────────────
  // Python handles the winotify notification; we also show a flash banner in
  // the overlay so the operator gets visual feedback in the app itself.
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let autoCollapseTimer: number | null = null;
    (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        unlisten = await listen<{
          ok: boolean;
          card: string;
          error?: string | null;
          shortcut: string;
        }>("scan-shortcut-result", (event) => {
          const p = event.payload;
          setFlash({
            key: `scan-${Date.now()}`,
            tone: p.ok ? "success" : "error",
            msg: p.ok ? `Carte scannée : ${p.card}` : `Scan : ${p.error ?? "erreur"}`,
          });
          doOpenRef.current();
          if (autoCollapseTimer) clearTimeout(autoCollapseTimer);
          autoCollapseTimer = window.setTimeout(() => {
            doCloseRef.current();
          }, 3000);
        });
      } catch { /* Non-Tauri environment */ }
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
      const res: any = await post(`/devices/${fav.deviceId}/door/open`, {
        doorNumber:   fav.doorNumber,
        pulseSeconds: fav.pulseSeconds,
      });
      // P3b-2: another PC drives this turnstile -- filed for it, not opened here.
      // That is information (blue), or a warning when the PC pilote is offline —
      // never the red error it used to be.
      const title = favoriteTitle(fav, index);
      if (res?.requested) {
        setFlash({ key, tone: res.targetConnected ? "info" : "warning", msg: `${title} : ${lowerFirst(doorRequestedMessage(res))}` });
      } else {
        setFlash({ key, tone: "success", msg: `${title} : porte ouverte` });
      }
    } catch (err) {
      setFlash({ key, tone: "error", msg: `${favoriteTitle(fav, index)} : ${String(err)}` });
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
  // Design ramp (light blue → primary → dark blue), from the docked edge outward.
  // White text on saturated blue: the same in light and dark mode.
  const pillAngle = isVertical ? "180deg" : "90deg";
  const pillGradient = `linear-gradient(${pillAngle}, #2D8CFF 0%, hsl(var(--primary)) 55%, #0C44AE 100%)`;

  // Panel border-radius — rounded on the side facing away from the edge.
  const panelRadius =
    edge === "right"  ? "20px 0 0 20px"
    : edge === "left" ? "0 20px 20px 0"
    : edge === "top"  ? "0 0 20px 20px"
    : /* bottom */      "20px 20px 0 0";

  // Accent stripe position on the panel (along the docked edge inside)
  const accentStripeStyle: React.CSSProperties = isVertical
    ? { height: 3, width: "100%", background:
        "linear-gradient(90deg, hsl(var(--primary)) 0%, hsl(var(--info)) 100%)",
        borderRadius: edge === "right" ? "20px 0 0 0" : "0 20px 0 0" }
    : { width: 3, height: "100%", background:
        "linear-gradient(180deg, hsl(var(--primary)) 0%, hsl(var(--info)) 100%)",
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
            chevrons/label inside the pill stays CONTAINED to the handle.
            Without it those inner elements would bleed above the expanded
            panel — you'd see the edge and the arrow tip poking
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
            className={`relative flex ${handleFlexDir} items-center justify-between text-white ${handleRadius} ${isVertical ? "h-full w-full px-1 py-3" : "h-full w-full px-3 py-1"}`}
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
              <ChevronIcon direction={chevronDir} className="text-white/90" />
            </div>

            {/* Star + « FAVORIS » label (vertical on a side edge) */}
            <div className={`relative z-10 flex ${isVertical ? "flex-col" : "flex-row"} items-center gap-2`}>
              <StarIcon size={15} />
              <span
                className="text-[11px] font-extrabold tracking-[0.18em]"
                style={isVertical ? { writingMode: "vertical-rl", transform: "rotate(180deg)" } : undefined}
              >
                FAVORIS
              </span>
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
              <ChevronIcon direction={chevronDir} className="text-white/90" />
            </div>
          </div>
        </div>

        {/* ── Expanded panel ────────────────────────────────────────────── */}
        {panelMounted && (
          <div className="absolute inset-0 z-10" style={panelTransitionStyle}>
            <div
              className="flex h-full w-full flex-col overflow-hidden text-foreground"
              style={{
                borderRadius: panelRadius,
                background: "hsl(var(--card) / 0.93)",
                backdropFilter: "blur(16px) saturate(1.3)",
                WebkitBackdropFilter: "blur(16px) saturate(1.3)",
                border: "1px solid hsl(var(--grey) / 0.32)",
                boxShadow:
                  "-14px 0 48px rgba(0,0,0,0.28), " +
                  "-3px 0 10px rgba(0,0,0,0.12), " +
                  "inset 1px 0 0 hsl(var(--foreground) / 0.04)",
              }}
            >
              {/* Top accent */}
              <div className="shrink-0" style={accentStripeStyle} />

              {/* Header */}
              <div className="flex shrink-0 items-center gap-2 border-b border-dashed border-grey/32 py-2.5 pl-3.5 pr-3">
                <span className="grid h-[22px] w-[22px] place-items-center rounded-[7px] bg-primary/14 text-primary">
                  <StarIcon size={12} />
                </span>
                <h1 className="m-0 flex-1 text-[12px] font-extrabold tracking-[0.16em] text-primary-ink">
                  ACCÈS RAPIDE
                </h1>
                {/* Manual sync — refetches from the remote server so new
                    dashboard favorites appear without waiting for auto-sync. */}
                <button
                  type="button"
                  disabled={syncing}
                  className="grid h-7 w-7 place-items-center rounded-full text-muted-foreground
                             transition-colors duration-150 hover:bg-muted hover:text-foreground
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
                      setFlash({ key: "sync", tone: "error", msg: `Synchronisation : ${String(e)}` });
                      setSyncing(false);
                    }
                  }}
                  aria-label="Synchroniser les favoris depuis le serveur"
                  title="Synchroniser les favoris depuis le serveur"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${syncing ? "animate-spin" : ""}`} />
                </button>
                <button
                  type="button"
                  className="grid h-7 w-7 place-items-center rounded-full text-muted-foreground
                             transition-colors duration-150 hover:bg-muted hover:text-foreground
                             focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/50"
                  onClick={doClose}
                  aria-label="Réduire le panneau favoris"
                  title="Réduire (Échap)"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>

              {/* Flash banner */}
              {flash && (() => {
                const FlashIcon = FLASH_ICON[flash.tone];
                return (
                  <div
                    role="status"
                    className={[
                      "mx-2.5 mt-2.5 flex shrink-0 items-start gap-2 rounded-[10px] px-2.5 py-2 text-[12px] font-semibold leading-[1.4]",
                      "animate-in fade-in slide-in-from-top-1 duration-200",
                      SOFT[flash.tone],
                    ].join(" ")}
                  >
                    <FlashIcon className="mt-px h-[15px] w-[15px] shrink-0" />
                    <span className="min-w-0 break-words">{flash.msg}</span>
                  </div>
                );
              })()}

              {/* List — single column for vertical panel (right/left anchor);
                  two-column grid for horizontal panel (top/bottom anchor)
                  so items use the extra width instead of leaving large
                  empty bands next to each row. */}
              <div
                className={[
                  "flex-1 overflow-y-auto overflow-x-hidden p-2.5",
                  isVertical ? "space-y-1.5" : "grid grid-cols-2 gap-1.5 content-start",
                ].join(" ")}
              >

                {loading && favorites.length === 0 && (
                  <div className={isVertical ? "space-y-1.5" : "contents"}>
                    {Array.from({ length: 4 }).map((_, i) => (
                      <div
                        key={i}
                        className="h-[52px] animate-pulse rounded-[14px] bg-muted"
                        style={{ opacity: 1 - i * 0.2, animationDelay: `${i * 80}ms` }}
                      />
                    ))}
                  </div>
                )}

                {!loading && favorites.length === 0 && (
                  <div
                    className={[
                      "mx-2 mt-[30px] rounded-[14px] border border-dashed border-grey/50 px-4 py-[26px] text-center text-[12.5px] leading-normal text-muted-foreground",
                      !isVertical && "col-span-2",
                    ].filter(Boolean).join(" ")}
                    style={{
                      opacity: panelOpen ? 1 : 0,
                      transform: panelOpen ? "translateY(0)" : "translateY(6px)",
                      transition: "opacity 280ms ease-out 80ms, transform 280ms cubic-bezier(0.22,0.9,0.28,1) 80ms",
                    }}
                  >
                    <div className="font-bold text-foreground">Aucun favori synchronisé</div>
                    Marquez des presets de portes comme favoris dans le tableau de bord MonClub, puis synchronisez.
                  </div>
                )}

                {favorites.map((fav, i) => {
                  const key    = String(fav.id);
                  const busy   = busyKey === key;
                  const hitTone: Tone | null = flash?.key === key ? flash.tone : null;
                  const isKb   = kbIndex === i;
                  const shortcut = typeof fav.favoriteShortcut === "string" ? fav.favoriteShortcut.trim() : "";
                  const EndIcon = hitTone ? FLASH_END_ICON[hitTone] : LockOpen;

                  const delay = panelOpen ? Math.min(i * 22, 200) : 0;

                  return (
                    <button
                      key={key}
                      type="button"
                      disabled={busy}
                      onClick={() => void handleOpen(fav, i)}
                      onMouseEnter={() => setKbIndex(i)}
                      className={[
                        "group relative flex w-full items-center gap-2.5 rounded-[14px] border px-2.5 py-2",
                        "text-left text-foreground transition-[background,border-color,transform,box-shadow] duration-150",
                        "disabled:opacity-60 focus:outline-none",
                        hitTone
                          ? ITEM_HIT[hitTone]
                          : isKb
                            ? "border-primary/45 bg-primary/6"
                            : "border-grey/28 bg-card/70 hover:border-primary/30 hover:bg-primary/5",
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
                          "grid h-[34px] w-[34px] shrink-0 place-items-center rounded-[10px] font-num text-[15px] font-extrabold",
                          "transition-colors duration-200",
                          hitTone === "success" ? "bg-success/18 text-success-ink" : "bg-primary/12 text-primary-ink",
                        ].join(" ")}
                      >
                        {slotBadge(fav.favoriteOrder ?? i)}
                      </span>

                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[13.5px] font-bold leading-tight">
                          {favoriteTitle(fav, i)}
                        </span>
                        <span className="mt-0.5 block truncate text-[11.5px] text-muted-foreground">
                          {fav.deviceName || "Appareil"} · {fav.pulseSeconds} s
                        </span>
                      </span>

                      {shortcut && (
                        <span
                          className="inline-flex h-5 shrink-0 items-center whitespace-nowrap rounded-[5px] border border-grey/40 bg-muted px-[5px] font-mono text-[10.5px] text-muted-foreground"
                          title={`Raccourci clavier : ${shortcut}`}
                        >
                          {shortcut}
                        </span>
                      )}

                      <span className="flex h-4 w-4 shrink-0 items-center justify-center">
                        {busy ? (
                          <svg className="h-4 w-4 animate-spin text-primary" viewBox="0 0 24 24" fill="none">
                            <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" opacity="0.2" />
                            <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
                          </svg>
                        ) : (
                          <EndIcon
                            className={[
                              "h-[15px] w-[15px] transition-colors duration-200",
                              hitTone
                                ? INK[hitTone]
                                : isKb
                                  ? "text-primary"
                                  : "text-grey group-hover:text-primary",
                            ].join(" ")}
                          />
                        )}
                      </span>
                    </button>
                  );
                })}
              </div>

              {/* Footer */}
              {!loading && favorites.length > 0 && (
                <div className="flex shrink-0 items-center justify-between gap-2 border-t border-dashed border-grey/32 px-3.5 py-2 text-[11px] text-muted-foreground">
                  <span className="font-bold uppercase tracking-[0.08em]">
                    {favorites.length} favori{favorites.length > 1 ? "s" : ""}
                  </span>
                  <span className="whitespace-nowrap">
                    <kbd className={KBD}>↑↓</kbd> choisir · <kbd className={KBD}>Entrée</kbd> ouvrir · <kbd className={KBD}>Échap</kbd> fermer
                  </span>
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

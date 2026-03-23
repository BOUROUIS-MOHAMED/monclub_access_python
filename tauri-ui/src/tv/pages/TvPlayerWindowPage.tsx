/**
 * TvPlayerWindowPage — A6: Binding-scoped TV player window
 *
 * Bootstraps from URL search params: ?bindingId=N&screenId=N
 * - Fetches render context every second (in-memory tick)
 * - Checks active snapshot ref every 5 ticks for changes
 * - Renders video / audio / image based on player state + render mode
 * - Persists state to backend every ~20 seconds or on meaningful change
 * - Debug overlay toggled with "D" key
 */

import React, { useEffect, useRef, useState, useCallback } from "react";
import { convertFileSrc } from "@tauri-apps/api/core";
import {
  getTvPlayerRenderContext,
  reportTvPlayerState,
  evaluateTvAdRuntime,
} from "@/tv/api";
import type { TvPlayerRenderContext, TvTimelineItemPresented } from "@/tv/api/types";
import TvLayout0 from "@/tv/layouts/TvLayout0";
import TvLayout1 from "@/tv/layouts/TvLayout1";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function useSearchParam(name: string): string | null {
  const params = new URLSearchParams(window.location.search);
  return params.get(name);
}

function toLocalSrc(filePath: string | null | undefined): string | null {
  if (!filePath) return null;
  try {
    return convertFileSrc(filePath);
  } catch {
    return null;
  }
}

function minuteOfDayLabel(m: number | null | undefined): string {
  if (m == null) return "--:--";
  const h = Math.floor(m / 60);
  const min = m % 60;
  return `${String(h).padStart(2, "0")}:${String(min).padStart(2, "0")}`;
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function IdlePlaceholder({ reason }: { reason: string | null }) {
  return (
    <div className="flex flex-col items-center justify-center w-full h-full bg-black text-white/30 gap-3 select-none">
      <div className="text-6xl font-bold tracking-widest">MonClub TV</div>
      <div className="text-sm">{reason ?? "En attente de contenu…"}</div>
    </div>
  );
}

function ErrorPlaceholder({ code, message }: { code: string | null; message: string | null }) {
  return (
    <div className="flex flex-col items-center justify-center w-full h-full bg-black text-red-400/60 gap-2 select-none">
      <div className="text-2xl">Erreur lecteur</div>
      {code && <div className="text-sm font-mono">{code}</div>}
      {message && <div className="text-xs max-w-sm text-center">{message}</div>}
    </div>
  );
}

interface DebugOverlayProps {
  bindingId: number;
  screenId: number | null;
  ctx: TvPlayerRenderContext;
  tickCount: number;
}

function DebugOverlay({ bindingId, screenId, ctx, tickCount }: DebugOverlayProps) {
  return (
    <div className="absolute top-2 left-2 right-2 z-50 bg-black/80 text-green-400 text-xs font-mono p-2 rounded pointer-events-none">
      <div>binding={bindingId} screen={screenId ?? "?"} tick={tickCount}</div>
      <div>state={ctx.playerState} mode={ctx.renderMode}</div>
      <div>
        snap={ctx.activeSnapshotId?.slice(0, 12) ?? "none"} v{ctx.activeSnapshotVersion ?? 0}
      </div>
      <div>
        time={minuteOfDayLabel(ctx.currentMinuteOfDay)} {ctx.currentDayOfWeek ?? ""}
        {" "}tz={ctx.timezone}
      </div>
      {ctx.currentVisual && (
        <div className="text-yellow-300">
          V: {ctx.currentVisual.mediaAssetId?.slice(0, 12)} {ctx.currentVisual.mediaType}
          {" "}renderable={String(ctx.currentVisual.assetRenderable)}
        </div>
      )}
      {ctx.currentAudio && (
        <div className="text-cyan-300">
          A: {ctx.currentAudio.mediaAssetId?.slice(0, 12)}
          {" "}renderable={String(ctx.currentAudio.assetRenderable)}
        </div>
      )}
      {ctx.fallbackReason && <div className="text-orange-400">fallback={ctx.fallbackReason}</div>}
      {ctx.videoMutedByAudio && <div className="text-purple-400">video muted by audio track</div>}
      {ctx.adOverrideActive && (
        <div className="text-pink-400">
          AD: {ctx.currentAdLayout} task={ctx.currentAdTaskId?.slice(0, 8)}
        </div>
      )}
      {ctx.lastRenderErrorCode && (
        <div className="text-red-400">err={ctx.lastRenderErrorCode}</div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Media renderers
// ---------------------------------------------------------------------------

interface AudioRendererProps {
  item: TvTimelineItemPresented;
}

function AudioRenderer({ item }: AudioRendererProps) {
  const src = toLocalSrc(item.assetPath);
  if (!src) return null;
  return (
    <audio key={src} src={src} autoPlay loop className="hidden" />
  );
}

interface AdRendererProps {
  ctx: TvPlayerRenderContext;
}

function AdRenderer({ ctx }: AdRendererProps) {
  const src = toLocalSrc(ctx.adAssetPath);
  if (!src) return <IdlePlaceholder reason="Fichier publicitaire introuvable" />;
  const mimeUpper = (ctx.adMimeType ?? "").toUpperCase();
  const isVideo = mimeUpper.startsWith("VIDEO") || mimeUpper.includes("MP4") || mimeUpper.includes("WEBM");
  if (isVideo) {
    return (
      <video
        key={src}
        src={src}
        autoPlay
        playsInline
        className="w-full h-full object-contain bg-black"
      />
    );
  }
  return (
    <img
      key={src}
      src={src}
      alt="Ad"
      className="w-full h-full object-contain bg-black"
    />
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

const TICK_MS = 1000;           // 1-second UI tick
const SNAPSHOT_CHECK_EVERY = 5; // check snapshot ref every N ticks
const PERSIST_EVERY_SEC = 20;   // persist freshness even without change

export default function TvPlayerWindowPage() {
  const bindingIdStr = useSearchParam("bindingId");
  const screenIdStr = useSearchParam("screenId");
  const bindingId = parseInt(bindingIdStr ?? "0", 10) || 0;
  const screenId = parseInt(screenIdStr ?? "0", 10) || null;

  const [ctx, setCtx] = useState<TvPlayerRenderContext | null>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [debugVisible, setDebugVisible] = useState(false);
  const tickRef = useRef(0);
  const lastSnapshotIdRef = useRef<string | null>(null);
  const lastPersistRef = useRef<number>(0);
  const lastStateKeyRef = useRef<string>("");

  // Toggle debug overlay with "D" key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "d" || e.key === "D") setDebugVisible((v) => !v);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // Derive a state key for change detection (no persist on every tick)
  const stateKey = useCallback((c: TvPlayerRenderContext): string => {
    return [
      c.activeSnapshotId ?? "",
      c.activeSnapshotVersion ?? 0,
      c.playerState,
      c.renderMode,
      c.fallbackReason ?? "",
      c.currentVisual?.itemId ?? "",
      c.currentAudio?.itemId ?? "",
      c.videoMutedByAudio ? "1" : "0",
    ].join("|");
  }, []);

  // Tick loop
  useEffect(() => {
    if (!bindingId) return;

    let cancelled = false;

    async function tick() {
      if (cancelled) return;
      tickRef.current += 1;
      const tick = tickRef.current;

      try {
        // persist=true only on snapshot-check ticks to avoid spam
        const shouldPersist = tick % SNAPSHOT_CHECK_EVERY === 0;
        const newCtx = await getTvPlayerRenderContext(bindingId, shouldPersist);
        // A7: trigger ad evaluation on snapshot-check ticks
        if (shouldPersist) {
          evaluateTvAdRuntime().catch(() => {/* fire and forget */});
        }
        if (cancelled) return;

        setFetchError(null);
        setCtx(newCtx);

        // Detect active snapshot change → force reload
        const newSnapId = newCtx.activeSnapshotId ?? null;
        if (lastSnapshotIdRef.current !== null && lastSnapshotIdRef.current !== newSnapId) {
          // Snapshot changed: force full persist / reload event
          lastSnapshotIdRef.current = newSnapId;
          persistState(newCtx, true);
          return;
        }
        lastSnapshotIdRef.current = newSnapId;

        // Persist on meaningful state change or freshness interval
        const nowSec = Date.now() / 1000;
        const key = stateKey(newCtx);
        const changed = key !== lastStateKeyRef.current;
        const freshnessExpired = (nowSec - lastPersistRef.current) >= PERSIST_EVERY_SEC;

        if (changed || freshnessExpired) {
          lastStateKeyRef.current = key;
          lastPersistRef.current = nowSec;
          persistState(newCtx, false);
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setFetchError(err instanceof Error ? err.message : String(err));
        }
      }
    }

    function persistState(c: TvPlayerRenderContext, force: boolean) {
      reportTvPlayerState(
        bindingId,
        {
          screen_id: c.screenId,
          active_snapshot_id: c.activeSnapshotId,
          active_snapshot_version: c.activeSnapshotVersion,
          current_day_of_week: c.currentDayOfWeek,
          current_minute_of_day: c.currentMinuteOfDay,
          current_visual_item_id: c.currentVisual?.itemId ?? null,
          current_audio_item_id: c.currentAudio?.itemId ?? null,
          current_visual_asset_id: c.currentVisual?.mediaAssetId ?? null,
          current_audio_asset_id: c.currentAudio?.mediaAssetId ?? null,
          current_visual_asset_path: c.currentVisual?.assetPath ?? null,
          current_audio_asset_path: c.currentAudio?.assetPath ?? null,
          player_state: c.playerState,
          render_mode: c.renderMode,
          fallback_reason: c.fallbackReason ?? null,
          video_muted_by_audio: c.videoMutedByAudio ? 1 : 0,
          last_render_error_code: c.lastRenderErrorCode ?? null,
          last_render_error_message: c.lastRenderErrorMessage ?? null,
          last_tick_at: c.evaluatedAt,
        },
        { force, freshnessSeconds: PERSIST_EVERY_SEC },
      ).catch(() => {/* fire and forget */});
    }

    // Run immediately then on interval
    tick();
    const id = setInterval(tick, TICK_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, [bindingId, stateKey]);

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  if (!bindingId) {
    return (
      <div className="w-screen h-screen bg-black text-white/30 flex items-center justify-center text-sm">
        Paramètre bindingId manquant
      </div>
    );
  }

  if (fetchError && !ctx) {
    return (
      <div className="w-screen h-screen bg-black text-red-400/60 flex items-center justify-center text-sm">
        {fetchError}
      </div>
    );
  }

  if (!ctx) {
    return (
      <div className="w-screen h-screen bg-black flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-white/20 border-t-white/80 rounded-full animate-spin" />
      </div>
    );
  }

  const state = ctx.playerState;
  const mode = ctx.renderMode;
  const audio = ctx.currentAudio;

  // Resolve layout (0 = Cool, 1 = Smart; fallback to 0)
  const resolvedLayoutId = ctx.layoutPresetId === 1 ? 1 : 0;

  // Compute audio progress for layout wiring
  const audioTitle = audio?.title ?? null;
  let audioProgressPercent = 0;
  if (audio && ctx.currentMinuteOfDay != null) {
    const start = audio.startMinuteOfDay ?? 0;
    const end = audio.endMinuteOfDay ?? 1440;
    const duration = Math.max(1, end - start);
    audioProgressPercent = Math.min(100, Math.max(0, ((ctx.currentMinuteOfDay - start) / duration) * 100));
  }

  // Compute visual asset src for layout wiring (video muted; AudioRenderer handles audio separately)
  const visual = ctx.currentVisual;
  const visualSrc = visual?.assetRenderable ? toLocalSrc(visual.assetPath) : null;
  const visualMimeType = visual?.mediaType ?? null;

  const layoutNode = resolvedLayoutId === 1
    ? <TvLayout1 audioTitle={audioTitle} audioProgressPercent={audioProgressPercent} visualSrc={visualSrc} visualMimeType={visualMimeType} bindingId={bindingId} />
    : <TvLayout0 audioTitle={audioTitle} audioProgressPercent={audioProgressPercent} visualSrc={visualSrc} visualMimeType={visualMimeType} bindingId={bindingId} />;

  // Hidden audio renderer (always present when audio is renderable and no ad audio override)
  const audioNode = !ctx.adOverrideActive && audio?.assetRenderable
    ? <AudioRenderer item={audio} />
    : null;

  // Determine main content layer
  let content: React.ReactNode;

  // A7: Ad override — layout always rendered behind so scheduled video keeps playing.
  // For FULL_SCREEN the AdRenderer covers the layout entirely (bg-black) but video continues.
  if (ctx.adOverrideActive && ctx.adAssetPath) {
    content = (
      <div className="relative w-full h-full">
        {/* Layout always behind — preserves video playback continuity */}
        <div className="absolute inset-0">{layoutNode}</div>
        {/* Ad renderer on top — covers layout visually */}
        <div className="absolute inset-0 z-10">
          <AdRenderer ctx={ctx} />
        </div>
      </div>
    );
  } else if (
    state === "BLOCKED_NO_BINDING" ||
    state === "BLOCKED_BINDING_DISABLED"
  ) {
    // Binding is missing or disabled — nothing meaningful to show
    content = <IdlePlaceholder reason={ctx.fallbackReason ?? null} />;
  } else if (state === "ERROR" && mode === "ERROR_FALLBACK") {
    content = (
      <ErrorPlaceholder
        code={ctx.lastRenderErrorCode ?? null}
        message={ctx.lastRenderErrorMessage ?? null}
      />
    );
  } else {
    // All other states (IDLE, BLOCKED_NO_ACTIVE_SNAPSHOT, BLOCKED_NO_RENDERABLE_ITEM,
    // PLAYING, etc.) — always show the layout so the UI is visible even with no content yet.
    content = layoutNode;
  }

  return (
    <div className="relative w-screen h-screen overflow-hidden bg-black">
      {debugVisible && (
        <DebugOverlay
          bindingId={bindingId}
          screenId={screenId}
          ctx={ctx}
          tickCount={tickRef.current}
        />
      )}
      {content}
      {/* Background audio playback */}
      <div className="hidden">{audioNode}</div>
    </div>
  );
}

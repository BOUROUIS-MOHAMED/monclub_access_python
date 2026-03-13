import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { getTvPlayerRenderContext, getTvPlayerStatus, postTvHostBindingRuntimeEvent, reportTvPlayerState } from "@/api/tv";
import type { TvPlayerRenderContext, TvPlayerTimelineItem } from "@/api/types";

type RuntimeEval = {
  minuteOfDay: number;
  dayOfWeek: string;
  currentVisual: TvPlayerTimelineItem | null;
  currentAudio: TvPlayerTimelineItem | null;
  playerState: string;
  renderMode: string;
  fallbackReason: string | null;
  lastRenderErrorCode: string | null;
  lastRenderErrorMessage: string | null;
  videoMutedByAudio: boolean;
  evaluatedAt: string;
};

const PLAYER_STATE_RENDERING = "RENDERING";
const PLAYER_STATE_FALLBACK_RENDERING = "FALLBACK_RENDERING";
const PLAYER_STATE_BLOCKED_NO_RENDERABLE_ITEM = "BLOCKED_NO_RENDERABLE_ITEM";
const PLAYER_STATE_BLOCKED_BINDING_DISABLED = "BLOCKED_BINDING_DISABLED";
const PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT = "BLOCKED_NO_ACTIVE_SNAPSHOT";
const PLAYER_STATE_ERROR = "ERROR";

const RENDER_VISUAL_ONLY = "VISUAL_ONLY";
const RENDER_AUDIO_ONLY = "AUDIO_ONLY";
const RENDER_VISUAL_AND_AUDIO = "VISUAL_AND_AUDIO";
const RENDER_IDLE_FALLBACK = "IDLE_FALLBACK";
const RENDER_ERROR_FALLBACK = "ERROR_FALLBACK";

const FALLBACK_NO_CURRENT_ITEM = "NO_CURRENT_ITEM";
const FALLBACK_NO_ACTIVE_SNAPSHOT = "NO_ACTIVE_SNAPSHOT";
const FALLBACK_BINDING_DISABLED = "BINDING_DISABLED";
const FALLBACK_VISUAL_INVALID = "VISUAL_ASSET_INVALID";
const FALLBACK_AUDIO_INVALID = "AUDIO_ASSET_INVALID";
const FALLBACK_BOTH_INVALID = "BOTH_ASSETS_INVALID";
const FALLBACK_SNAPSHOT_INVALID = "SNAPSHOT_INVALID";
const FALLBACK_INTERNAL = "INTERNAL_ERROR";

const TICK_MS = 1000;
const CONTEXT_POLL_MS = 4000;
const PERSIST_REFRESH_MS = 20000;

function boolish(v: unknown): boolean {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    return s === "1" || s === "true" || s === "yes" || s === "on";
  }
  return false;
}

function toNum(v: unknown, fallback = 0): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function minuteClock(timezone?: string | null): { minute: number; day: string } {
  try {
    const parts = new Intl.DateTimeFormat("en-GB", {
      timeZone: timezone || "UTC",
      hour12: false,
      weekday: "long",
      hour: "2-digit",
      minute: "2-digit",
    }).formatToParts(new Date());
    const byType = new Map(parts.map((p) => [p.type, p.value]));
    const hh = Number(byType.get("hour") || 0);
    const mm = Number(byType.get("minute") || 0);
    const day = String(byType.get("weekday") || "").toUpperCase();
    return {
      minute: (Number.isFinite(hh) ? hh : 0) * 60 + (Number.isFinite(mm) ? mm : 0),
      day,
    };
  } catch {
    const now = new Date();
    const day = now.toLocaleDateString("en-GB", { weekday: "long" }).toUpperCase();
    return { minute: now.getHours() * 60 + now.getMinutes(), day };
  }
}

function selectCurrent(items: TvPlayerTimelineItem[] | undefined, minute: number): TvPlayerTimelineItem | null {
  const list = (items || []).filter((item) => {
    const start = toNum(item.startMinuteOfDay, -1);
    const end = toNum(item.endMinuteOfDay, -1);
    return start >= 0 && end > start && start <= minute && minute < end;
  });
  if (list.length === 0) return null;
  list.sort((a, b) => {
    const sa = toNum(a.startMinuteOfDay, 0);
    const sb = toNum(b.startMinuteOfDay, 0);
    if (sa !== sb) return sa - sb;
    return String(a.itemId || "").localeCompare(String(b.itemId || ""));
  });
  return list[0] || null;
}

function isRenderable(item: TvPlayerTimelineItem | null): boolean {
  if (!item) return false;
  return boolish(item.assetRenderable) && !!String(item.assetPath || "").trim();
}

function evaluateRuntime(base: TvPlayerRenderContext | null): RuntimeEval {
  const tz = String(base?.timezone || "UTC");
  const clock = minuteClock(tz);

  const currentVisual = selectCurrent(base?.visualItems, clock.minute);
  const currentAudio = selectCurrent(base?.audioItems, clock.minute);

  if (!base || !base.ok) {
    return {
      minuteOfDay: clock.minute,
      dayOfWeek: clock.day,
      currentVisual: null,
      currentAudio: null,
      playerState: PLAYER_STATE_ERROR,
      renderMode: RENDER_ERROR_FALLBACK,
      fallbackReason: FALLBACK_INTERNAL,
      lastRenderErrorCode: "CONTEXT_UNAVAILABLE",
      lastRenderErrorMessage: String(base?.error || "Player context unavailable."),
      videoMutedByAudio: false,
      evaluatedAt: new Date().toISOString(),
    };
  }

  if (base.bindingEnabled === false) {
    return {
      minuteOfDay: clock.minute,
      dayOfWeek: clock.day,
      currentVisual: null,
      currentAudio: null,
      playerState: PLAYER_STATE_BLOCKED_BINDING_DISABLED,
      renderMode: RENDER_IDLE_FALLBACK,
      fallbackReason: FALLBACK_BINDING_DISABLED,
      lastRenderErrorCode: null,
      lastRenderErrorMessage: null,
      videoMutedByAudio: false,
      evaluatedAt: new Date().toISOString(),
    };
  }

  const hasActiveSnapshot = !!String(base.activeSnapshotId || "") && toNum(base.activeSnapshotVersion, 0) > 0;
  if (!hasActiveSnapshot) {
    return {
      minuteOfDay: clock.minute,
      dayOfWeek: clock.day,
      currentVisual: null,
      currentAudio: null,
      playerState: PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT,
      renderMode: RENDER_IDLE_FALLBACK,
      fallbackReason: FALLBACK_NO_ACTIVE_SNAPSHOT,
      lastRenderErrorCode: null,
      lastRenderErrorMessage: null,
      videoMutedByAudio: false,
      evaluatedAt: new Date().toISOString(),
    };
  }

  const vExists = !!currentVisual;
  const aExists = !!currentAudio;
  const vOk = isRenderable(currentVisual);
  const aOk = isRenderable(currentAudio);

  let playerState = PLAYER_STATE_BLOCKED_NO_RENDERABLE_ITEM;
  let renderMode = RENDER_IDLE_FALLBACK;
  let fallbackReason: string | null = FALLBACK_NO_CURRENT_ITEM;
  let lastRenderErrorCode: string | null = null;
  let lastRenderErrorMessage: string | null = null;

  if (!vExists && !aExists) {
    playerState = PLAYER_STATE_BLOCKED_NO_RENDERABLE_ITEM;
    renderMode = RENDER_IDLE_FALLBACK;
    fallbackReason = FALLBACK_NO_CURRENT_ITEM;
  } else if (vOk && aOk) {
    playerState = PLAYER_STATE_RENDERING;
    renderMode = RENDER_VISUAL_AND_AUDIO;
    fallbackReason = null;
  } else if (vOk && !aExists) {
    playerState = PLAYER_STATE_RENDERING;
    renderMode = RENDER_VISUAL_ONLY;
    fallbackReason = null;
  } else if (aOk && !vExists) {
    playerState = PLAYER_STATE_RENDERING;
    renderMode = RENDER_AUDIO_ONLY;
    fallbackReason = null;
  } else if (vOk && aExists && !aOk) {
    playerState = PLAYER_STATE_FALLBACK_RENDERING;
    renderMode = RENDER_VISUAL_ONLY;
    fallbackReason = FALLBACK_AUDIO_INVALID;
    lastRenderErrorMessage = "Current audio asset is invalid/unreadable.";
  } else if (aOk && vExists && !vOk) {
    playerState = PLAYER_STATE_FALLBACK_RENDERING;
    renderMode = RENDER_AUDIO_ONLY;
    fallbackReason = FALLBACK_VISUAL_INVALID;
    lastRenderErrorMessage = "Current visual asset is invalid/unreadable.";
  } else {
    playerState = PLAYER_STATE_ERROR;
    renderMode = RENDER_ERROR_FALLBACK;
    fallbackReason = vExists && aExists ? FALLBACK_BOTH_INVALID : vExists ? FALLBACK_VISUAL_INVALID : FALLBACK_AUDIO_INVALID;
    lastRenderErrorCode = "ASSET_INVALID";
    lastRenderErrorMessage = "Current render asset is invalid or unreadable.";
  }

  let videoMutedByAudio = false;
  if (String(currentVisual?.mediaType || "").toUpperCase() === "VIDEO") {
    if (aOk) {
      videoMutedByAudio = true;
    } else {
      videoMutedByAudio = !boolish(currentVisual?.videoAudioEnabled);
    }
  }

  return {
    minuteOfDay: clock.minute,
    dayOfWeek: clock.day,
    currentVisual,
    currentAudio,
    playerState,
    renderMode,
    fallbackReason,
    lastRenderErrorCode,
    lastRenderErrorMessage,
    videoMutedByAudio,
    evaluatedAt: new Date().toISOString(),
  };
}

function fallbackFileUrl(path: string): string {
  const normalized = String(path || "").replace(/\\/g, "/");
  if (/^https?:\/\//i.test(normalized)) return normalized;
  if (/^file:\/\//i.test(normalized)) return normalized;
  if (/^[a-zA-Z]:\//.test(normalized)) return `file:///${encodeURI(normalized)}`;
  if (normalized.startsWith("/")) return `file://${encodeURI(normalized)}`;
  return `file://${encodeURI(normalized)}`;
}

function shorten(value: unknown, max = 18): string {
  const s = String(value || "");
  if (s.length <= max) return s;
  return `${s.slice(0, max)}...`;
}

function adLayoutStyle(layout: string): Record<string, string> {
  const key = String(layout || "FULL_SCREEN").toUpperCase();
  if (key === "ADS_1_4_H") return { left: "0%", top: "0%", width: "25%", height: "100%" };
  if (key === "ADS_1_2_H") return { left: "0%", top: "0%", width: "50%", height: "100%" };
  if (key === "ADS_3_4_H") return { left: "0%", top: "0%", width: "75%", height: "100%" };
  if (key === "ADS_1_4_V") return { left: "0%", top: "0%", width: "100%", height: "25%" };
  if (key === "ADS_1_2_V") return { left: "0%", top: "0%", width: "100%", height: "50%" };
  if (key === "ADS_3_4_V") return { left: "0%", top: "0%", width: "100%", height: "75%" };
  return { left: "0%", top: "0%", width: "100%", height: "100%" };
}

function isFullScreenAdLayout(layout: string): boolean {
  return String(layout || "FULL_SCREEN").toUpperCase() === "FULL_SCREEN";
}

export default function TvPlayerWindowPage() {
  const [params] = useSearchParams();
  const bindingId = Number(params.get("bindingId") || 0);
  const screenId = Number(params.get("screenId") || 0);
  const initialDebug = boolish(params.get("debug") || "0");

  const [baseContext, setBaseContext] = useState<TvPlayerRenderContext | null>(null);
  const [runtimeEval, setRuntimeEval] = useState<RuntimeEval | null>(null);
  const [converter, setConverter] = useState<((path: string) => string) | null>(null);
  const [showDebug, setShowDebug] = useState(initialDebug);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const lastPersistSignatureRef = useRef<string>("");
  const lastPersistAtRef = useRef<number>(0);
  const persistInFlightRef = useRef(false);
  const lastSnapshotRef = useRef<string>("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const mod = await import("@tauri-apps/api/core");
        const fn = (mod as any)?.convertFileSrc;
        if (!cancelled && typeof fn === "function") {
          setConverter(() => fn as (path: string) => string);
        }
      } catch {
        if (!cancelled) setConverter(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const toAssetUrl = useCallback((path: string | null | undefined): string => {
    const raw = String(path || "").trim();
    if (!raw) return "";
    if (converter) {
      try {
        return converter(raw);
      } catch {
        return fallbackFileUrl(raw);
      }
    }
    return fallbackFileUrl(raw);
  }, [converter]);

  const loadContext = useCallback(async (reason: "init" | "poll" | "notify" | "manual" = "poll") => {
    if (!Number.isFinite(bindingId) || bindingId <= 0 || !Number.isFinite(screenId) || screenId <= 0) {
      setError("Invalid player context. bindingId and screenId are required.");
      return;
    }

    if (reason === "init" || reason === "manual") {
      setLoading(true);
    }

    try {
      const [statusRes, contextRes] = await Promise.all([
        getTvPlayerStatus(bindingId),
        getTvPlayerRenderContext(bindingId, { persist: false }),
      ]);
      if (!statusRes.ok) {
        throw new Error(String(statusRes.error || "BINDING_NOT_FOUND"));
      }
      setBaseContext(contextRes);
      setError(contextRes.ok ? null : String(contextRes.error || "Failed to resolve player context."));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (reason === "init" || reason === "manual") {
        setLoading(false);
      }
    }
  }, [bindingId, screenId]);

  useEffect(() => {
    void loadContext("init");
  }, [loadContext]);

  useEffect(() => {
    if (!(bindingId > 0)) return;
    const windowId = `tv-player-binding-${bindingId}`;
    void postTvHostBindingRuntimeEvent(bindingId, { eventType: "WINDOW_LAUNCHED", windowId }).catch(() => undefined);
    return () => {
      void postTvHostBindingRuntimeEvent(bindingId, { eventType: "WINDOW_CLOSED", windowId }).catch(() => undefined);
    };
  }, [bindingId]);

  useEffect(() => {
    const id = window.setInterval(() => {
      void loadContext("poll");
    }, CONTEXT_POLL_MS);
    return () => window.clearInterval(id);
  }, [loadContext]);

  useEffect(() => {
    const listener = (ev: Event) => {
      const custom = ev as CustomEvent<any>;
      const payload = custom?.detail || {};
      const eventBinding = Number(payload?.bindingId || payload?.binding_id || 0);
      if (eventBinding > 0 && eventBinding !== bindingId) return;
      void loadContext("notify");
    };
    window.addEventListener("tv-binding-snapshot-changed", listener as EventListener);
    return () => window.removeEventListener("tv-binding-snapshot-changed", listener as EventListener);
  }, [bindingId, loadContext]);

  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key.toLowerCase() === "d") {
        setShowDebug((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    const id = window.setInterval(() => {
      setRuntimeEval(evaluateRuntime(baseContext));
    }, TICK_MS);
    setRuntimeEval(evaluateRuntime(baseContext));
    return () => window.clearInterval(id);
  }, [baseContext]);

  const persistState = useCallback(async (runtime: RuntimeEval, force = false) => {
    if (!(bindingId > 0) || !baseContext || !baseContext.ok) return;
    if (persistInFlightRef.current) return;

    const visual = runtime.currentVisual;
    const audio = runtime.currentAudio;
    const payload = {
      screen_id: Number(baseContext.screenId || screenId || 0),
      active_snapshot_id: baseContext.activeSnapshotId || null,
      active_snapshot_version: baseContext.activeSnapshotVersion || null,
      current_day_of_week: runtime.dayOfWeek,
      current_minute_of_day: runtime.minuteOfDay,
      current_visual_item_id: visual?.itemId || null,
      current_audio_item_id: audio?.itemId || null,
      current_visual_asset_id: visual?.mediaAssetId || null,
      current_audio_asset_id: audio?.mediaAssetId || null,
      current_visual_asset_path: visual?.assetPath || null,
      current_audio_asset_path: audio?.assetPath || null,
      player_state: runtime.playerState,
      render_mode: runtime.renderMode,
      fallback_reason: runtime.fallbackReason,
      video_muted_by_audio: runtime.videoMutedByAudio,
      ad_override_active: adOverrideActive,
      current_ad_task_id: adOverrideActive ? Number(baseContext?.currentAdTaskId || 0) || null : null,
      current_ad_media_id: adOverrideActive ? (baseContext?.currentAdMediaId || null) : null,
      ad_layout: adOverrideActive ? (baseContext?.adLayout || null) : null,
      ad_audio_override_active: adAudioOverride,
      ad_runtime_state: adOverrideActive ? (baseContext?.adDisplayState || "DISPLAYING") : null,
      ad_runtime_message: adOverrideActive ? null : (baseContext?.adFallbackReason || null),
      last_render_error_code: runtime.lastRenderErrorCode,
      last_render_error_message: runtime.lastRenderErrorMessage,
      last_tick_at: runtime.evaluatedAt,
      last_snapshot_check_at: new Date().toISOString(),
    };

    const signature = JSON.stringify([
      payload.active_snapshot_id,
      payload.active_snapshot_version,
      payload.current_visual_item_id,
      payload.current_audio_item_id,
      payload.player_state,
      payload.render_mode,
      payload.fallback_reason,
      payload.last_render_error_code,
      payload.last_render_error_message,
      payload.video_muted_by_audio,
    ]);

    const now = Date.now();
    const changed = signature !== lastPersistSignatureRef.current;
    const freshnessDue = (now - lastPersistAtRef.current) >= PERSIST_REFRESH_MS;
    if (!force && !changed && !freshnessDue) return;

    let eventType = changed ? "PLAYER_STATE_CHANGED" : "PLAYER_REEVALUATED";
    const snapshotId = String(payload.active_snapshot_id || "");
    if (changed && snapshotId && snapshotId !== lastSnapshotRef.current) {
      eventType = "PLAYER_RELOADED";
    }

    persistInFlightRef.current = true;
    try {
      await reportTvPlayerState(bindingId, {
        state: payload,
        eventType,
        force,
        freshnessSeconds: 20,
      });
      lastPersistSignatureRef.current = signature;
      lastPersistAtRef.current = now;
      lastSnapshotRef.current = snapshotId;
    } catch {
      // best effort: rendering should stay isolated even if report fails
    } finally {
      persistInFlightRef.current = false;
    }
  }, [baseContext, bindingId, screenId, adOverrideActive, adAudioOverride]);

  useEffect(() => {
    if (!runtimeEval) return;
    void persistState(runtimeEval, false);
  }, [runtimeEval, persistState]);

  const visualSrc = useMemo(() => {
    const path = runtimeEval?.currentVisual?.assetPath;
    return path ? toAssetUrl(path) : "";
  }, [runtimeEval?.currentVisual?.assetPath, toAssetUrl]);

  const audioSrc = useMemo(() => {
    const path = runtimeEval?.currentAudio?.assetPath;
    return path ? toAssetUrl(path) : "";
  }, [runtimeEval?.currentAudio?.assetPath, toAssetUrl]);

  const renderMode = String(runtimeEval?.renderMode || RENDER_IDLE_FALLBACK);
  const adOverrideActive = boolish(baseContext?.adOverrideActive);
  const adAudioOverride = adOverrideActive && boolish(baseContext?.adAudioOverrideActive ?? true);
  const adLayout = String(baseContext?.adLayout || "FULL_SCREEN").toUpperCase();
  const adSrc = useMemo(() => {
    const path = String(baseContext?.adAssetPath || "").trim();
    return path ? toAssetUrl(path) : "";
  }, [baseContext?.adAssetPath, toAssetUrl]);
  const adStyle = useMemo(() => adLayoutStyle(adLayout), [adLayout]);

  const showVisual = renderMode === RENDER_VISUAL_ONLY || renderMode === RENDER_VISUAL_AND_AUDIO;
  const showAudio = !adAudioOverride && (renderMode === RENDER_AUDIO_ONLY || renderMode === RENDER_VISUAL_AND_AUDIO);

  const visualType = String(runtimeEval?.currentVisual?.mediaType || "").toUpperCase();
  const visualMuted = adAudioOverride ? true : boolish(runtimeEval?.videoMutedByAudio);
  const showBaseVisual = showVisual && (!adOverrideActive || !isFullScreenAdLayout(adLayout));

  const handleVisualError = useCallback(async () => {
    if (!runtimeEval) return;
    await reportTvPlayerState(bindingId, {
      state: {
        screen_id: Number(baseContext?.screenId || screenId || 0),
        active_snapshot_id: baseContext?.activeSnapshotId || null,
        active_snapshot_version: baseContext?.activeSnapshotVersion || null,
        current_day_of_week: runtimeEval.dayOfWeek,
        current_minute_of_day: runtimeEval.minuteOfDay,
        current_visual_item_id: runtimeEval.currentVisual?.itemId || null,
        current_audio_item_id: runtimeEval.currentAudio?.itemId || null,
        current_visual_asset_id: runtimeEval.currentVisual?.mediaAssetId || null,
        current_audio_asset_id: runtimeEval.currentAudio?.mediaAssetId || null,
        current_visual_asset_path: runtimeEval.currentVisual?.assetPath || null,
        current_audio_asset_path: runtimeEval.currentAudio?.assetPath || null,
        player_state: PLAYER_STATE_ERROR,
        render_mode: RENDER_ERROR_FALLBACK,
        fallback_reason: FALLBACK_VISUAL_INVALID,
        video_muted_by_audio: runtimeEval.videoMutedByAudio,
        last_render_error_code: "VISUAL_RENDER_FAILED",
        last_render_error_message: "Visual asset became unreadable during render.",
        last_tick_at: new Date().toISOString(),
      },
      eventType: "PLAYER_ERROR",
      force: true,
      freshnessSeconds: 20,
    }).catch(() => undefined);
    await loadContext("manual");
  }, [runtimeEval, bindingId, baseContext?.screenId, baseContext?.activeSnapshotId, baseContext?.activeSnapshotVersion, screenId, loadContext]);

  const handleAudioError = useCallback(async () => {
    if (!runtimeEval) return;
    await reportTvPlayerState(bindingId, {
      state: {
        screen_id: Number(baseContext?.screenId || screenId || 0),
        active_snapshot_id: baseContext?.activeSnapshotId || null,
        active_snapshot_version: baseContext?.activeSnapshotVersion || null,
        current_day_of_week: runtimeEval.dayOfWeek,
        current_minute_of_day: runtimeEval.minuteOfDay,
        current_visual_item_id: runtimeEval.currentVisual?.itemId || null,
        current_audio_item_id: runtimeEval.currentAudio?.itemId || null,
        current_visual_asset_id: runtimeEval.currentVisual?.mediaAssetId || null,
        current_audio_asset_id: runtimeEval.currentAudio?.mediaAssetId || null,
        current_visual_asset_path: runtimeEval.currentVisual?.assetPath || null,
        current_audio_asset_path: runtimeEval.currentAudio?.assetPath || null,
        player_state: PLAYER_STATE_FALLBACK_RENDERING,
        render_mode: showVisual ? RENDER_VISUAL_ONLY : RENDER_ERROR_FALLBACK,
        fallback_reason: FALLBACK_AUDIO_INVALID,
        video_muted_by_audio: false,
        last_render_error_code: "AUDIO_RENDER_FAILED",
        last_render_error_message: "Audio asset became unreadable during render.",
        last_tick_at: new Date().toISOString(),
      },
      eventType: "PLAYER_ERROR",
      force: true,
      freshnessSeconds: 20,
    }).catch(() => undefined);
    await loadContext("manual");
  }, [runtimeEval, bindingId, baseContext?.screenId, baseContext?.activeSnapshotId, baseContext?.activeSnapshotVersion, screenId, showVisual, loadContext]);

  const handleAdError = useCallback(async () => {
    await reportTvPlayerState(bindingId, {
      state: {
        screen_id: Number(baseContext?.screenId || screenId || 0),
        active_snapshot_id: baseContext?.activeSnapshotId || null,
        active_snapshot_version: baseContext?.activeSnapshotVersion || null,
        current_day_of_week: runtimeEval?.dayOfWeek || null,
        current_minute_of_day: runtimeEval?.minuteOfDay || null,
        current_visual_item_id: runtimeEval?.currentVisual?.itemId || null,
        current_audio_item_id: runtimeEval?.currentAudio?.itemId || null,
        player_state: PLAYER_STATE_ERROR,
        render_mode: RENDER_ERROR_FALLBACK,
        fallback_reason: FALLBACK_INTERNAL,
        ad_override_active: true,
        current_ad_task_id: baseContext?.currentAdTaskId || null,
        current_ad_media_id: baseContext?.currentAdMediaId || null,
        ad_layout: baseContext?.adLayout || null,
        ad_audio_override_active: true,
        ad_runtime_state: String(baseContext?.adDisplayState || "DISPLAY_ABORTED_LOCAL"),
        ad_runtime_message: "Ad media render failed.",
        last_render_error_code: "AD_RENDER_FAILED",
        last_render_error_message: "Ad asset became unreadable during render.",
        last_tick_at: new Date().toISOString(),
      },
      eventType: "PLAYER_ERROR",
      force: true,
      freshnessSeconds: 20,
    }).catch(() => undefined);
    await loadContext("manual");
  }, [bindingId, baseContext, runtimeEval, screenId, loadContext]);

  return (
    <div className="relative h-screen w-screen overflow-hidden bg-black text-white">
      {showBaseVisual && visualSrc ? (
        visualType === "IMAGE" ? (
          <img src={visualSrc} alt="TV visual" className="h-full w-full object-cover" />
        ) : (
          <video
            key={`${runtimeEval?.currentVisual?.itemId || "video"}:${visualSrc}:${visualMuted ? "m" : "u"}`}
            src={visualSrc}
            className="h-full w-full object-cover"
            autoPlay
            playsInline
            loop
            muted={visualMuted}
            onError={() => void handleVisualError()}
          />
        )
      ) : renderMode === RENDER_ERROR_FALLBACK && !adOverrideActive ? (
        <div className="flex h-full w-full items-center justify-center bg-zinc-950 text-center text-sm text-red-300">
          <div>
            <div className="font-semibold">Player Error Fallback</div>
            <div className="opacity-80">Current content is unavailable.</div>
          </div>
        </div>
      ) : (
        <div className="h-full w-full bg-black" />
      )}

      {adOverrideActive && adSrc && (
        <div className={isFullScreenAdLayout(adLayout) ? "absolute inset-0 z-20" : "absolute z-20"} style={adStyle}>
          <video
            key={`ad:${baseContext?.currentAdTaskId || "task"}:${adSrc}:${adLayout}`}
            src={adSrc}
            className="h-full w-full object-cover"
            autoPlay
            playsInline
            loop
            muted={false}
            onError={() => void handleAdError()}
          />
        </div>
      )}

      {showAudio && audioSrc && (
        <audio
          key={`${runtimeEval?.currentAudio?.itemId || "audio"}:${audioSrc}`}
          src={audioSrc}
          autoPlay
          loop
          onError={() => void handleAudioError()}
        />
      )}

      {showDebug && (
        <div className="absolute inset-0 pointer-events-none">
          <div className="pointer-events-auto absolute left-3 top-3 right-3 rounded border border-zinc-700 bg-black/70 p-3 text-xs text-zinc-100">
            <div className="mb-2 flex items-center justify-between">
              <div className="font-semibold">TV Player Debug (Binding Scoped)</div>
              <Button
                variant="outline"
                size="sm"
                className="h-7 px-2 text-[11px]"
                onClick={() => void loadContext("manual")}
                disabled={loading}
              >
                <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
                Refresh
              </Button>
            </div>

            {error && (
              <div className="mb-2 rounded border border-red-700 bg-red-950/40 px-2 py-1 text-red-200">
                <div className="flex items-center gap-2"><AlertTriangle className="h-3.5 w-3.5" /> {error}</div>
              </div>
            )}

            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              <div>bindingId: <span className="font-mono">{bindingId || "-"}</span></div>
              <div>screenId: <span className="font-mono">{screenId || "-"}</span></div>
              <div>snapshot: <span className="font-mono">{String(baseContext?.activeSnapshotVersion || "-")}</span></div>
              <div>timezone: <span className="font-mono">{String(baseContext?.timezone || "-")}</span></div>
              <div>playerState: <span className="font-mono">{String(runtimeEval?.playerState || "-")}</span></div>
              <div>renderMode: <span className="font-mono">{String(runtimeEval?.renderMode || "-")}</span></div>
              <div>fallback: <span className="font-mono">{String(runtimeEval?.fallbackReason || "-")}</span></div>
              <div>minute: <span className="font-mono">{String(runtimeEval?.minuteOfDay ?? "-")}</span></div>
              <div>adOverride: <span className="font-mono">{adOverrideActive ? "ON" : "OFF"}</span></div>
              <div>adTask: <span className="font-mono">{String(baseContext?.currentAdTaskId || "-")}</span></div>
              <div>adLayout: <span className="font-mono">{String(baseContext?.adLayout || "-")}</span></div>
            </div>

            <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-2">
              <div className="rounded border border-zinc-700 px-2 py-1">
                <div className="font-medium">Visual</div>
                <div>item: <span className="font-mono">{String(runtimeEval?.currentVisual?.itemId || "-")}</span></div>
                <div>asset: <span className="font-mono">{shorten(runtimeEval?.currentVisual?.assetPath || "-")}</span></div>
                <div>type: <span className="font-mono">{String(runtimeEval?.currentVisual?.mediaType || "-")}</span></div>
              </div>
              <div className="rounded border border-zinc-700 px-2 py-1">
                <div className="font-medium">Audio</div>
                <div>item: <span className="font-mono">{String(runtimeEval?.currentAudio?.itemId || "-")}</span></div>
                <div>asset: <span className="font-mono">{shorten(runtimeEval?.currentAudio?.assetPath || "-")}</span></div>
                <div>mutedByAudioRule: <span className="font-mono">{runtimeEval?.videoMutedByAudio ? "YES" : "NO"}</span></div>
                <div>adAudioOverride: <span className="font-mono">{adAudioOverride ? "YES" : "NO"}</span></div>
                <div>adState: <span className="font-mono">{String(baseContext?.adDisplayState || "-")}</span></div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


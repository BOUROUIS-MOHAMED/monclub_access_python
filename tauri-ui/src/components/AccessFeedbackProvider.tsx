import {
  useCallback,
  createContext,
  useContext,
  useEffect,
  useEffectEvent,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { get, openSSE } from "@/api/client";
import type { AppConfig, FeedbackEvent, FeedbackEventType } from "@/api/types";
import {
  getFeedbackSoundUrl,
  isFeedbackAnimationEnabled,
  isFeedbackSoundEnabled,
} from "@/lib/feedback";

interface FeedbackBeaconState {
  firedAt: number;
  seq: number;
  type: FeedbackEventType;
}

interface AccessFeedbackContextValue {
  beacon: FeedbackBeaconState | null;
  config: AppConfig | null;
}

const AccessFeedbackContext = createContext<AccessFeedbackContextValue | null>(null);

function preloadAudio(map: Map<string, HTMLAudioElement>, src: string): HTMLAudioElement {
  const existing = map.get(src);
  if (existing) {
    return existing;
  }
  const audio = new Audio(src);
  audio.preload = "auto";
  audio.volume = 0.72;
  map.set(src, audio);
  return audio;
}

export function AccessFeedbackProvider({ children }: { children: ReactNode }) {
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [beacon, setBeacon] = useState<FeedbackBeaconState | null>(null);
  const audioCacheRef = useRef<Map<string, HTMLAudioElement>>(new Map());
  const seenPushRunsRef = useRef<Set<number>>(new Set());

  const loadConfig = useCallback(async () => {
    try {
      const response = await get<any>("/config");
      const nextConfig = (response?.config || response || null) as AppConfig | null;
      if (nextConfig) {
        setConfig(nextConfig);
      }
    } catch {
      // Keep the last-known config when the local API is temporarily reconnecting.
    }
  }, []);

  useEffect(() => {
    void loadConfig();
  }, [loadConfig]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return undefined;
    }
    const handleConfigUpdate = (event: Event) => {
      const nextConfig = (event as CustomEvent<AppConfig>).detail;
      if (nextConfig && typeof nextConfig === "object") {
        setConfig(nextConfig);
      }
    };
    window.addEventListener("access-feedback-config-updated", handleConfigUpdate as EventListener);
    return () => {
      window.removeEventListener("access-feedback-config-updated", handleConfigUpdate as EventListener);
    };
  }, []);

  const handleFeedbackEvent = useEffectEvent((eventType: FeedbackEventType, payload: FeedbackEvent) => {
    if (!config) {
      return;
    }

    if (eventType === "device_push_success" && config.push_success_repeat_mode === "per_run") {
      const syncRunId = Number(payload.syncRunId || 0);
      if (syncRunId > 0) {
        if (seenPushRunsRef.current.has(syncRunId)) {
          return;
        }
        seenPushRunsRef.current.add(syncRunId);
        if (seenPushRunsRef.current.size > 100) {
          seenPushRunsRef.current.clear();
          seenPushRunsRef.current.add(syncRunId);
        }
      }
    }

    if (isFeedbackSoundEnabled(config, eventType)) {
      const soundUrl = getFeedbackSoundUrl(config, eventType);
      const audio = preloadAudio(audioCacheRef.current, soundUrl);
      try {
        audio.pause();
        audio.currentTime = 0;
        void audio.play().catch(() => {
          // Ignore autoplay or asset failures.
        });
      } catch {
        // Ignore playback failures.
      }
    }

    if (isFeedbackAnimationEnabled(config, eventType)) {
      setBeacon({
        firedAt: Date.now(),
        seq: Number(payload.seq || Date.now()),
        type: eventType,
      });
    }
  });

  // Effect Events are intentionally omitted from deps so the SSE connection
  // stays stable across config/beacon renders.
  useEffect(() => {
    const es = openSSE(
      "/feedback/events",
      (type, data) => {
        if (type !== "device_push_success" && type !== "sync_completed_success") {
          return;
        }
        if (!data || typeof data !== "object") {
          return;
        }
        handleFeedbackEvent(type as FeedbackEventType, data as FeedbackEvent);
      },
      {
        onReconnect: () => {
          seenPushRunsRef.current.clear();
        },
      },
    );

    return () => {
      es.close();
      for (const audio of audioCacheRef.current.values()) {
        try {
          audio.pause();
          audio.src = "";
        } catch {
          // Ignore cleanup failures.
        }
      }
      audioCacheRef.current.clear();
    };
  }, [loadConfig]);

  return (
    <AccessFeedbackContext.Provider value={{ beacon, config }}>
      {children}
    </AccessFeedbackContext.Provider>
  );
}

export function useAccessFeedback() {
  const value = useContext(AccessFeedbackContext);
  if (!value) {
    throw new Error("useAccessFeedback must be used inside AccessFeedbackProvider");
  }
  return value;
}

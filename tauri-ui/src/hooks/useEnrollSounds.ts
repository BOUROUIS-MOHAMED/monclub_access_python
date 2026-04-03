import { useCallback, useEffect, useRef } from "react";

const SOUND_MAP: Record<string, string> = {
  sample_captured: "/sounds/scan-captured.mp3",
  sample_rejected: "/sounds/scan-rejected.mp3",
  success:         "/sounds/enroll-success.mp3",
  failed:          "/sounds/enroll-failed.mp3",
};

/**
 * Preloads enrollment sound files and exposes a playSound() function.
 * Uses HTML5 Audio API — works in Tauri webview without plugins.
 *
 * Sound files go in `public/sounds/`. If a file is missing,
 * play() fails silently (try/catch).
 */
export function useEnrollSounds(enabled: boolean) {
  const audioRef = useRef<Map<string, HTMLAudioElement>>(new Map());

  // Preload on mount
  useEffect(() => {
    const map = new Map<string, HTMLAudioElement>();
    for (const [key, src] of Object.entries(SOUND_MAP)) {
      try {
        const audio = new Audio(src);
        audio.volume = 0.6;
        audio.load();
        map.set(key, audio);
      } catch {
        // missing file or unsupported — skip
      }
    }
    audioRef.current = map;
    return () => {
      for (const a of map.values()) {
        try { a.pause(); a.src = ""; } catch { /* ignore */ }
      }
    };
  }, []);

  const playSound = useCallback(
    (key: string) => {
      if (!enabled) return;
      const audio = audioRef.current.get(key);
      if (!audio) return;
      try {
        audio.currentTime = 0;
        audio.play().catch(() => {
          // autoplay policy or missing file — silent fail
        });
      } catch {
        // ignore
      }
    },
    [enabled],
  );

  return { playSound };
}

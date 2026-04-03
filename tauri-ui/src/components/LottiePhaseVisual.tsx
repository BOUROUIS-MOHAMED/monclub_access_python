import { useEffect, useMemo, useState } from "react";
import Lottie from "lottie-react";
import type { EnrollPhase } from "./EnrollOverlay";

// Animation files are placed by the user in public/animations/.
// We fetch them at runtime. If a file is missing → returns null → CSS fallback.
const ANIM_URLS: Record<string, string> = {
  "fingerprint-scan":     "/animations/fingerprint-scan.json",
  "fingerprint-success":  "/animations/fingerprint-success.json",
  "fingerprint-rejected": "/animations/fingerprint-rejected.json",
  "scanner-init":         "/animations/scanner-init.json",
  "processing":           "/animations/processing.json",
  "error-x":              "/animations/error-x.json",
  "connecting":           "/animations/connecting.json",
};

type AnimConfig = {
  key: string;
  loop: boolean;
};

const PHASE_ANIM: Record<EnrollPhase, AnimConfig | null> = {
  idle:            null,
  connecting:      { key: "connecting",           loop: true },
  device_init:     { key: "scanner-init",          loop: true },
  wait_finger:     { key: "fingerprint-scan",      loop: true },
  lift_finger:     { key: "fingerprint-success",   loop: false },
  sample_rejected: { key: "fingerprint-rejected",  loop: true },
  processing:      { key: "processing",            loop: true },
  push:            { key: "processing",            loop: true },
  success:         { key: "fingerprint-success",   loop: false },
  failed:          { key: "error-x",               loop: false },
  cancelled:       null,
};

// Cache fetched animation data
const cache = new Map<string, object | null>();

function useAnimData(key: string | undefined): object | null {
  const [data, setData] = useState<object | null>(key ? cache.get(key) ?? null : null);

  useEffect(() => {
    if (!key) { setData(null); return; }
    if (cache.has(key)) { setData(cache.get(key)!); return; }

    const url = ANIM_URLS[key];
    if (!url) { cache.set(key, null); return; }

    let cancelled = false;
    fetch(url)
      .then((r) => { if (!r.ok) throw new Error(`${r.status}`); return r.json(); })
      .then((json) => { cache.set(key, json); if (!cancelled) setData(json); })
      .catch(() => { cache.set(key, null); });
    return () => { cancelled = true; };
  }, [key]);

  return data;
}

/**
 * Renders a Lottie animation for the given enrollment phase.
 * Returns null if the animation JSON is missing → caller falls back to CSS.
 */
export default function LottiePhaseVisual({ phase }: { phase: EnrollPhase }): React.ReactElement | null {
  const config = useMemo(() => PHASE_ANIM[phase] ?? null, [phase]);
  const animData = useAnimData(config?.key);

  if (!config || !animData) return null;

  return (
    <div className="flex items-center justify-center w-40 h-40">
      <Lottie
        animationData={animData}
        loop={config.loop}
        autoplay
        rendererSettings={{ preserveAspectRatio: "xMidYMid meet" }}
        className="w-36 h-36"
      />
    </div>
  );
}

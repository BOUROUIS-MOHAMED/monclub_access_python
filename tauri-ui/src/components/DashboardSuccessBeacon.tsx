import { useEffect, useState } from "react";
import Lottie from "lottie-react";
import { useAccessFeedback } from "@/components/AccessFeedbackProvider";
import { DEFAULT_FEEDBACK_ANIMATIONS } from "@/lib/feedback";
import { cn } from "@/lib/utils";

const animationCache = new Map<string, object | null>();

function useAnimationData(url: string | null): object | null {
  const [data, setData] = useState<object | null>(url ? animationCache.get(url) ?? null : null);

  useEffect(() => {
    if (!url) {
      setData(null);
      return;
    }
    if (animationCache.has(url)) {
      setData(animationCache.get(url) ?? null);
      return;
    }

    let cancelled = false;
    fetch(url)
      .then((response) => {
        if (!response.ok) {
          throw new Error(String(response.status));
        }
        return response.json();
      })
      .then((json) => {
        animationCache.set(url, json);
        if (!cancelled) {
          setData(json);
        }
      })
      .catch(() => {
        animationCache.set(url, null);
        if (!cancelled) {
          setData(null);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [url]);

  return data;
}

export default function DashboardSuccessBeacon({ className }: { className?: string }) {
  const { beacon } = useAccessFeedback();
  const [activeBeacon, setActiveBeacon] = useState(beacon);

  useEffect(() => {
    if (!beacon) {
      return undefined;
    }
    setActiveBeacon(beacon);
    const timeoutId = window.setTimeout(() => {
      setActiveBeacon((current) => (current?.seq === beacon.seq ? null : current));
    }, 2400);
    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [beacon]);

  const animationUrl = activeBeacon ? DEFAULT_FEEDBACK_ANIMATIONS[activeBeacon.type] : null;
  const animationData = useAnimationData(animationUrl);
  const isPush = activeBeacon?.type === "device_push_success";
  const label = isPush ? "Push OK" : "Sync OK";

  return (
    <div className={cn("flex h-7 min-w-[98px] items-center justify-end", className)}>
      <div
        className={cn(
          "flex items-center gap-1.5 rounded-full border px-2 py-0.5 transition-all duration-300",
          activeBeacon
            ? isPush
              ? "border-emerald-400/50 bg-emerald-500/10 text-emerald-100 shadow-[0_0_24px_rgba(16,185,129,0.16)]"
              : "border-amber-300/55 bg-amber-400/10 text-amber-100 shadow-[0_0_24px_rgba(251,191,36,0.18)]"
            : "pointer-events-none scale-95 opacity-0",
        )}
      >
        <span className="text-[10px] font-semibold uppercase tracking-[0.18em]">
          {label}
        </span>
        <div className="flex h-9 w-9 items-center justify-center overflow-hidden">
          {animationData ? (
            <Lottie
              animationData={animationData}
              autoplay
              loop={false}
              className="h-9 w-9"
              rendererSettings={{ preserveAspectRatio: "xMidYMid meet" }}
            />
          ) : (
            <span
              className={cn(
                "h-2.5 w-2.5 rounded-full animate-pulse",
                isPush ? "bg-emerald-300" : "bg-amber-300",
              )}
            />
          )}
        </div>
      </div>
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import type { EnrollPhase } from "@/components/EnrollOverlay";

const PHASE_TIMEOUTS: Partial<Record<EnrollPhase, number>> = {
  connecting:  15_000,
  device_init: 10_000,
  wait_finger: 25_000,
  processing:  10_000,
  push:        20_000,
};

/**
 * Returns true if the current phase has exceeded its expected duration.
 * Resets whenever the phase changes. Phases without a configured timeout
 * never time out (success, failed, cancelled, idle, lift_finger, sample_rejected).
 */
export function usePhaseTimeout(phase: EnrollPhase): boolean {
  const [timedOut, setTimedOut] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setTimedOut(false);
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = null;

    const ms = PHASE_TIMEOUTS[phase];
    if (ms) {
      timerRef.current = setTimeout(() => setTimedOut(true), ms);
    }

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [phase]);

  return timedOut;
}

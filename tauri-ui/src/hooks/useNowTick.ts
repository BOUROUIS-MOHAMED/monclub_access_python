// Display-only clock for « il y a … » labels (relativeTimeFr) on pages that have no timer of
// their own. It only re-renders the page: no request is made (owner decision 2026-10-16).
import { useEffect, useState } from "react";

export function useNowTick(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}

import { useState, useCallback, useRef, useEffect } from "react";
import { post, get } from "@/api/client";
import type { ScannerStatus, DiscoverStatus, DiscoveredDevice } from "@/api/types";

export function useScanCard() {
  const [status, setStatus] = useState<ScannerStatus>({
    state: "idle",
    error: "",
    lastResult: null,
  });
  const [discovering, setDiscovering] = useState(false);
  const [discoveredDevices, setDiscoveredDevices] = useState<DiscoveredDevice[]>([]);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const startScan = useCallback(async (overrides?: { mode?: string; ip?: string }) => {
    try {
      await post("/scanner/start", overrides || {});
      // Poll status until idle/error
      pollRef.current = setInterval(async () => {
        try {
          const res = await get<{ ok: boolean; scanner: ScannerStatus }>("/scanner/status");
          setStatus(res.scanner);
          if (res.scanner.state === "idle" || res.scanner.state === "error") {
            if (pollRef.current) clearInterval(pollRef.current);
          }
        } catch {
          // ignore poll errors
        }
      }, 300);
    } catch (e) {
      setStatus((s) => ({ ...s, state: "error", error: String(e) }));
    }
  }, []);

  const stopScan = useCallback(async () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    try {
      await post("/scanner/stop");
    } catch {
      // ignore
    }
    setStatus({ state: "idle", error: "", lastResult: null });
  }, []);

  const startDiscover = useCallback(async () => {
    setDiscovering(true);
    setDiscoveredDevices([]);
    try {
      await post("/scanner/discover");
      const poll = setInterval(async () => {
        try {
          const res = await get<{ ok: boolean } & DiscoverStatus>("/scanner/discover/status");
          setDiscoveredDevices(res.devices || []);
          if (!res.running) {
            clearInterval(poll);
            setDiscovering(false);
          }
        } catch {
          clearInterval(poll);
          setDiscovering(false);
        }
      }, 1000);
    } catch {
      setDiscovering(false);
    }
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  return { status, startScan, stopScan, startDiscover, discovering, discoveredDevices };
}

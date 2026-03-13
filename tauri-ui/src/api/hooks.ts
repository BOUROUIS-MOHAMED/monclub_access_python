// React hooks — one per API endpoint group, using real /api/v2 paths
import { useCallback, useEffect, useRef, useState } from "react";
import { get, post, patch, del, openSSE, ApiError } from "./client";
import type {
  StatusResponse, LoginRequest, LoginResponse, AppConfig,
  UserDto, AgentStatusResponse, AgentDeviceSnap,
  UpdateStatusResponse, LogLine, LocalFingerprintDto, PopupEvent,
} from "./types";

// ── generic fetch hook ──
function useApi<T>(fetcher: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try { setData(await fetcher()); }
    catch (e) { setError(e instanceof ApiError ? e.message : String(e)); }
    finally { setLoading(false); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { load(); }, [load]);
  return { data, loading, error, reload: load };
}

// ── Unified status polling (GET /api/v2/status) ──
export function useStatus(pollMs = 5000) {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    try { setStatus(await get<StatusResponse>("/status")); setError(null); }
    catch (e) { setError(e instanceof ApiError ? e.message : String(e)); }
  }, []);
  useEffect(() => { load(); const id = setInterval(load, pollMs); return () => clearInterval(id); }, [load, pollMs]);
  return { status, error, reload: load };
}

// ── Auth (POST /api/v2/auth/login, /auth/logout) ──
export function useAuth() {
  const [loading, setLoading] = useState(false);
  const login = async (req: LoginRequest) => {
    setLoading(true);
    try { return await post<LoginResponse>("/auth/login", req); } finally { setLoading(false); }
  };
  const logout = async () => { setLoading(true); try { await post("/auth/logout"); } finally { setLoading(false); } };
  return { login, logout, loading };
}

// ── Config (GET/PATCH /api/v2/config) ──
export function useConfig() {
  const result = useApi<AppConfig>(() => get("/config"));
  const save = async (partial: Partial<AppConfig>) => { await patch("/config", partial); result.reload(); };
  return { ...result, save };
}

// ── Sync cache devices (GET /api/v2/sync/cache/devices) ──
export function useDevices() {
  return useApi<{ devices: any[] }>(() => get("/sync/cache/devices"));
}

// ── Sync cache users (GET /api/v2/sync/cache/users) ──
export function useUsers(limit = 5000) {
  return useApi<{ users: UserDto[]; total: number }>(
    () => get("/sync/cache/users", { limit: String(limit) }), [limit],
  );
}

// ── Sync trigger (POST /api/v2/sync/now) ──
export function useSyncTrigger() {
  const [loading, setLoading] = useState(false);
  const trigger = async () => { setLoading(true); try { await post("/sync/now"); } finally { setLoading(false); } };
  return { trigger, loading };
}

// ── Agent (GET /api/v2/agent/status + /agent/devices) ──
export function useAgentStatus(pollMs = 3000) {
  const [status, setStatus] = useState<AgentStatusResponse | null>(null);
  const [devices, setDevices] = useState<AgentDeviceSnap>({});
  const load = useCallback(async () => {
    try {
      const [s, d] = await Promise.all([
        get<AgentStatusResponse>("/agent/status"),
        get<{ devices: AgentDeviceSnap }>("/agent/devices"),
      ]);
      setStatus(s); setDevices(d.devices);
    } catch { /* silent poll fail */ }
  }, []);
  useEffect(() => { load(); const id = setInterval(load, pollMs); return () => clearInterval(id); }, [load, pollMs]);
  return { status, devices, reload: load };
}

// ── Updates (GET /api/v2/update/status) ──
export function useUpdates() {
  return useApi<UpdateStatusResponse>(() => get("/update/status"));
}

// ── Fingerprints (GET /api/v2/fingerprints) ──
export function useFingerprints() {
  const result = useApi<{ fingerprints: LocalFingerprintDto[] }>(() => get("/fingerprints"));
  const remove = async (id: number) => { await del(`/fingerprints/${id}`); result.reload(); };
  return { ...result, remove };
}

// ── Logs SSE (GET /api/v2/logs/stream) ──
export function useLogStream(maxLines = 2000) {
  const [lines, setLines] = useState<LogLine[]>([]);
  const esRef = useRef<EventSource | null>(null);
  useEffect(() => {
    const es = openSSE("/logs/stream", (type, data) => {
      if (type === "log" && data && typeof data === "object") {
        setLines((prev) => {
          const n = [...prev, data as LogLine];
          return n.length > maxLines ? n.slice(-maxLines) : n;
        });
      }
    });
    esRef.current = es;
    return () => es.close();
  }, [maxLines]);
  const clear = () => setLines([]);
  return { lines, clear };
}

// ── Enroll actions ──
export function useEnroll() {
  return {
    start: (params: Record<string, any>) => post("/enroll/start", params),
    cancel: () => post("/enroll/cancel"),
    status: () => get<any>("/enroll/status"),
    listFingerprints: async () => { const r = await get<{ fingerprints: any[] }>("/fingerprints"); return r.fingerprints || []; },
    deleteFingerprint: (id: number) => del(`/fingerprints/${id}`),
  };
}

// ── PullSDK actions ──
export function usePullSdk() {
  return {
    connect: (deviceId: number) => post(`/devices/${deviceId}/connect`),
    disconnect: (deviceId: number) => post(`/devices/${deviceId}/disconnect`),
    doorOpen: (deviceId: number, doorNumber: number, pulseSeconds: number) =>
      post(`/devices/${deviceId}/door/open`, { doorNumber, pulseSeconds }),
    getInfo: (deviceId: number) => get<any>(`/devices/${deviceId}/info`),
  };
}

// ── Popup SSE stream (GET /api/v2/agent/events — popup events only) ──
// Sends popup data to localStorage for the separate popup window to display.
// The popup window stays open permanently and polls localStorage.
// History is always collected (for the notification drawer).
export function usePopupStream(maxHistory = 50) {
  const [popup, setPopup] = useState<PopupEvent | null>(null);
  const [history, setHistory] = useState<PopupEvent[]>([]);
  const [badgeCount, setBadgeCount] = useState(0);
  const esRef = useRef<EventSource | null>(null);

  const sendToPopupWindow = useCallback((evt: PopupEvent) => {
    // Write event to localStorage — the popup window polls this
    try {
      localStorage.setItem("popupEvent", JSON.stringify(evt));
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    const es = openSSE("/agent/events", (type, data) => {
      if (type === "popup" && data && typeof data === "object") {
        const evt: PopupEvent = { ...data, receivedAt: Date.now() };

        // Always add to history (for notification drawer)
        setBadgeCount((c) => c + 1);
        setHistory((prev) => {
          const n = [evt, ...prev];
          return n.length > maxHistory ? n.slice(0, maxHistory) : n;
        });

        // Send to popup window (if popupEnabled for this device)
        if (evt.popupEnabled !== false) {
          sendToPopupWindow(evt);
        }

        // Also set popup state for fallback overlay (browser mode)
        setPopup(evt);
      }
    });
    esRef.current = es;
    return () => { es.close(); };
  }, [maxHistory, sendToPopupWindow]);

  const dismiss = useCallback(() => setPopup(null), []);
  const clearBadge = useCallback(() => setBadgeCount(0), []);
  const clearHistory = useCallback(() => { setHistory([]); setBadgeCount(0); }, []);

  // Helper to open the popup window (used by header button)
  const openPopupWindow = useCallback(async () => {
    try {
      const { WebviewWindow } = await import("@tauri-apps/api/webviewWindow");
      const label = "access_popup";
      // Don't close existing — just focus it if it exists
      try {
        const existing = await WebviewWindow.getByLabel(label);
        if (existing) {
          await existing.setFocus();
          return;
        }
      } catch { /* ignore */ }

      // Create new popup window (laptop-size, stays open)
      new WebviewWindow(label, {
        url: "/popup",
        title: "MonClub Access — Écran Notification",
        width: 1024,
        height: 600,
        resizable: true,
        decorations: true,
        alwaysOnTop: true,
        center: true,
        focus: true,
      });
    } catch {
      // Fallback: browser mode — open in new tab
      window.open("/popup", "access_popup", "width=1024,height=600");
    }
  }, []);

  // Helper to send a fake test notification
  const sendTestNotification = useCallback(() => {
    const fakeEvt: PopupEvent = {
      eventId: `test-${Date.now().toString(36)}`,
      title: "Test — Accès OK",
      message: "Notification de test envoyée depuis le Dashboard",
      imagePath: "",
      popupShowImage: true,
      userFullName: "Jean-Pierre Dupont",
      userImage: "",
      userValidFrom: "2025-09-01T00:00:00Z",
      userValidTo: "2026-09-01T00:00:00Z",
      userMembershipId: 42,
      userPhone: "+212 6 12 34 56 78",
      deviceId: 1,
      deviceName: "Entrée Principale (TEST)",
      allowed: true,
      reason: "ALLOW_CARD",
      scanMode: "RFID",
      popupDurationSec: 5,
      popupEnabled: true,
      winNotifyEnabled: false,
      receivedAt: Date.now(),
    };

    // Add to history
    setBadgeCount((c) => c + 1);
    setHistory((prev) => [fakeEvt, ...prev].slice(0, maxHistory));

    // Send to popup window
    sendToPopupWindow(fakeEvt);

    // Set popup state for fallback
    setPopup(fakeEvt);
  }, [maxHistory, sendToPopupWindow]);

  return { popup, history, badgeCount, dismiss, clearBadge, clearHistory, openPopupWindow, sendTestNotification };
}

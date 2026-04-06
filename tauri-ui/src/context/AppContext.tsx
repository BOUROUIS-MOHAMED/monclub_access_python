import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from "react";
import { get, post, openSSE, ApiError } from "@/api/client";
import type { StatusResponse, LoginRequest, LoginResponse } from "@/api/types";

interface AppState {
  status: StatusResponse | null;
  coreReady: boolean;
  loading: boolean;
  error: string | null;
}

interface AppCtx extends AppState {
  refreshStatus: () => Promise<void>;
  login: (req: LoginRequest) => Promise<LoginResponse>;
  logout: () => Promise<void>;
  syncNow: () => Promise<void>;
}

const Ctx = createContext<AppCtx | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AppState>({
    status: null, coreReady: false, loading: true, error: null,
  });

  const refreshStatus = useCallback(async () => {
    try {
      const s = await get<StatusResponse>("/status");
      setState({ status: s, coreReady: true, loading: false, error: null });
    } catch (e) {
      // If the server is completely unreachable (fetch failed / network error),
      // keep loading=true so the splash stays visible instead of showing login.
      const isNetworkError = !(e instanceof ApiError);
      setState((p) => ({
        ...p,
        loading: isNetworkError && !p.status,   // stay on splash until first successful response
        coreReady: p.coreReady,
        error: String(e),
      }));
    }
  }, []);

  const login = useCallback(async (req: LoginRequest) => {
    const res = await post<LoginResponse>("/auth/login", req);
    await refreshStatus();
    return res;
  }, [refreshStatus]);

  const logout = useCallback(async () => {
    await post("/auth/logout");
    await refreshStatus();
  }, [refreshStatus]);

  const syncNow = useCallback(async () => {
    await post("/sync/now");
    setTimeout(refreshStatus, 1500);
  }, [refreshStatus]);

  useEffect(() => {
    refreshStatus();
    const id = setInterval(refreshStatus, 5000);
    return () => clearInterval(id);
  }, [refreshStatus]);

  useEffect(() => {
    const sse = openSSE(
      "/status/stream",
      (type, data) => {
        if (type !== "status" || !data || typeof data !== "object") return;
        setState((prev) => ({
          ...prev,
          status: data as StatusResponse,
          coreReady: true,
          loading: false,
          error: null,
        }));
      },
      {
        onReconnect: () => { void refreshStatus(); },
      },
    );
    return () => sse.close();
  }, [refreshStatus]);

  return (
    <Ctx.Provider value={{ ...state, refreshStatus, login, logout, syncNow }}>
      {children}
    </Ctx.Provider>
  );
}

export function useApp(): AppCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useApp must be inside AppProvider");
  return c;
}


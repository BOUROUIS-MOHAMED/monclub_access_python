/**
 * TvAuthContext — Auth state for the TV shell window.
 *
 * The TV window runs on its own API server (port 8789) and owns its own auth.
 * This context polls GET http://127.0.0.1:8789/api/v2/tv/auth/status every 5s
 * to reflect login state, and provides login/logout helpers that hit the TV
 * backend directly. MonClub Access is NOT required.
 *
 * SSO behaviour: if Access is co-installed and the user logs in here, the
 * Python layer mirrors the token to Access on a best-effort basis (and vice
 * versa), so a single login covers both apps.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

import { LOCAL_API_BASE_URL_TV, LOCAL_API_PREFIX } from "@/config/appConst";
import type { LoginRequest, LoginResponse, StatusResponse } from "@/api/types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface TvAuthState {
  status: StatusResponse | null;
  /** True once we have received at least one successful response. */
  coreReady: boolean;
  loading: boolean;
  error: string | null;
}

interface TvAuthCtx extends TvAuthState {
  refreshStatus: () => Promise<void>;
  login: (req: LoginRequest) => Promise<LoginResponse>;
  logout: () => Promise<void>;
}

// ---------------------------------------------------------------------------
// Helpers — direct fetch to Access backend (port 8788)
// ---------------------------------------------------------------------------

const TV_BASE = LOCAL_API_BASE_URL_TV;
const PFX = LOCAL_API_PREFIX;

async function accessGet<T>(path: string): Promise<T> {
  const res = await fetch(`${TV_BASE}${PFX}${path}`, {
    headers: { Accept: "application/json" },
  });
  const text = await res.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(text || `HTTP ${res.status}`);
  }
  if (!res.ok) {
    const j = json as Record<string, unknown>;
    throw new Error((j?.error as string) || `HTTP ${res.status}`);
  }
  return json as T;
}

async function accessPost<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${TV_BASE}${PFX}${path}`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: body != null ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(text || `HTTP ${res.status}`);
  }
  if (!res.ok) {
    const j = json as Record<string, unknown>;
    throw new Error((j?.error as string) || `HTTP ${res.status}`);
  }
  return json as T;
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const TvAuthCtx = createContext<TvAuthCtx | null>(null);

export function TvAuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<TvAuthState>({
    status: null,
    coreReady: false,
    loading: true,
    error: null,
  });

  const refreshStatus = useCallback(async () => {
    try {
      const s = await accessGet<StatusResponse>("/tv/auth/status");
      setState({ status: s, coreReady: true, loading: false, error: null });
    } catch (e) {
      // If the TV server is completely unreachable (network error),
      // keep loading=true so the splash stays visible instead of showing login.
      const isNetworkError = !(e instanceof Error) || e.message.startsWith("HTTP");
      const networkDown = !isNetworkError || e instanceof TypeError;
      setState((prev) => ({
        ...prev,
        loading: networkDown && !prev.status,
        coreReady: prev.coreReady,
        error: String(e),
      }));
    }
  }, []);

  const login = useCallback(
    async (req: LoginRequest): Promise<LoginResponse> => {
      const res = await accessPost<LoginResponse>("/tv/auth/login", req);
      await refreshStatus();
      return res;
    },
    [refreshStatus],
  );

  const logout = useCallback(async () => {
    await accessPost("/tv/auth/logout");
    await refreshStatus();
  }, [refreshStatus]);

  useEffect(() => {
    void refreshStatus();
    const id = setInterval(() => void refreshStatus(), 5000);
    return () => clearInterval(id);
  }, [refreshStatus]);

  return (
    <TvAuthCtx.Provider value={{ ...state, refreshStatus, login, logout }}>
      {children}
    </TvAuthCtx.Provider>
  );
}

export function useTvAuth(): TvAuthCtx {
  const c = useContext(TvAuthCtx);
  if (!c) throw new Error("useTvAuth must be inside TvAuthProvider");
  return c;
}

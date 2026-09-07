import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { get, post } from "@/api/client";
import type {
  AccessPcListResponse,
  PcIdentityStatusResponse,
  PcRegistrationResponse,
} from "@/api/types";
import { useApp } from "@/context/AppContext";
import { shouldShowPcSetup } from "@/lib/pcIdentityState";

interface PcIdentityContextValue {
  status: PcIdentityStatusResponse | null;
  pcs: AccessPcListResponse | null;
  loading: boolean;
  pcsLoading: boolean;
  error: string | null;
  requiresSetup: boolean;
  showSetup: boolean;
  refreshStatus: () => Promise<void>;
  loadPcs: () => Promise<void>;
  register: (name: string) => Promise<PcRegistrationResponse>;
  adopt: (pcId: number) => Promise<PcRegistrationResponse>;
  continueWithoutRegistration: () => void;
  openSetup: () => void;
}

const PcIdentityCtx = createContext<PcIdentityContextValue | null>(null);

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function PcIdentityProvider({ children }: { children: ReactNode }) {
  const { status: appStatus } = useApp();
  const loggedIn = appStatus?.session?.loggedIn ?? false;
  const [status, setStatus] = useState<PcIdentityStatusResponse | null>(null);
  const [pcs, setPcs] = useState<AccessPcListResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [pcsLoading, setPcsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [bypassed, setBypassed] = useState(false);

  const refreshStatus = useCallback(async () => {
    setLoading(true);
    try {
      const next = await get<PcIdentityStatusResponse>("/pc-identity/status");
      setStatus(next);
      setError(null);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadPcs = useCallback(async () => {
    setPcsLoading(true);
    try {
      const next = await get<AccessPcListResponse>("/pc-identity/pcs");
      setPcs(next);
      setError(null);
    } catch (requestError) {
      setError(errorMessage(requestError));
      throw requestError;
    } finally {
      setPcsLoading(false);
    }
  }, []);

  const register = useCallback(async (name: string) => {
    const result = await post<PcRegistrationResponse>("/pc-identity/register", { name });
    setBypassed(false);
    await refreshStatus();
    return result;
  }, [refreshStatus]);

  const adopt = useCallback(async (pcId: number) => {
    const result = await post<PcRegistrationResponse>(`/pc-identity/pcs/${pcId}/adopt`);
    setBypassed(false);
    await refreshStatus();
    return result;
  }, [refreshStatus]);

  useEffect(() => {
    if (!loggedIn) {
      setStatus(null);
      setPcs(null);
      setError(null);
      setBypassed(false);
      return;
    }
    void refreshStatus();
  }, [loggedIn, refreshStatus]);

  const requiresSetup = shouldShowPcSetup(status, false);
  const showSetup = loggedIn && shouldShowPcSetup(status, bypassed);
  const value = useMemo<PcIdentityContextValue>(() => ({
    status,
    pcs,
    loading,
    pcsLoading,
    error,
    requiresSetup,
    showSetup,
    refreshStatus,
    loadPcs,
    register,
    adopt,
    continueWithoutRegistration: () => setBypassed(true),
    openSetup: () => setBypassed(false),
  }), [
    status,
    pcs,
    loading,
    pcsLoading,
    error,
    requiresSetup,
    showSetup,
    refreshStatus,
    loadPcs,
    register,
    adopt,
  ]);

  return <PcIdentityCtx.Provider value={value}>{children}</PcIdentityCtx.Provider>;
}

export function usePcIdentity(): PcIdentityContextValue {
  const context = useContext(PcIdentityCtx);
  if (!context) throw new Error("usePcIdentity must be inside PcIdentityProvider");
  return context;
}

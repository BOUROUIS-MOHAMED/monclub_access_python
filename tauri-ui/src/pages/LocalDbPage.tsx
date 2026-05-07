import React, { useState, useCallback, useMemo, useEffect, useRef } from "react";
import { get, post } from "@/api/client";
import { DataTable } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Database,
  Download,
  Loader2,
  RefreshCw,
  Lock,
  LockOpen,
  Key,
  Eye,
  EyeOff,
  X,
} from "lucide-react";
import * as XLSX from "xlsx";
import {
  buildSmartColumns,
  CellDetailModal,
  EMPTY_FK_CONTEXT,
  CLOSED_MODAL,
  type FkLookupContext,
  type CellDetailModalState,
} from "@/components/ui/smart-columns";
import { TooltipProvider } from "@/components/ui/tooltip";

// ─── session helpers ──────────────────────────────────────────────────────────

const UNLOCK_KEY = "monclub:localdb-unlock";
const SESSION_MS = 5 * 60 * 1000;

function readUnlock(): { ok: boolean; rem: number } {
  try {
    const raw = sessionStorage.getItem(UNLOCK_KEY);
    if (!raw) return { ok: false, rem: 0 };
    const { exp } = JSON.parse(raw) as { exp: number };
    const rem = exp - Date.now();
    if (rem <= 0) {
      sessionStorage.removeItem(UNLOCK_KEY);
      return { ok: false, rem: 0 };
    }
    return { ok: true, rem };
  } catch {
    return { ok: false, rem: 0 };
  }
}

function fmtMs(ms: number): string {
  const s = Math.ceil(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

// ─── lock screen ──────────────────────────────────────────────────────────────

function LockScreen({ onUnlock }: { onUnlock: () => void }) {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleConfirm = useCallback(async () => {
    if (!password.trim() || loading) return;
    setLoading(true);
    setError(null);
    try {
      const res = await post<{ ok: boolean; error?: string }>(
        "/auth/verify-admin-password",
        { password },
        25_000,
      );
      if (res.ok) {
        const exp = Date.now() + SESSION_MS;
        sessionStorage.setItem(UNLOCK_KEY, JSON.stringify({ exp }));
        setDialogOpen(false);
        setPassword("");
        onUnlock();
      } else {
        setError(res.error ?? "Mot de passe incorrect");
      }
    } catch (e: any) {
      const msg = e?.name === "AbortError" || (e?.message ?? "").includes("timed out")
        ? "Le serveur ne r\u00e9pond pas. V\u00e9rifiez votre connexion internet."
        : (e?.message ?? "Erreur d'authentification");
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [password, loading, onUnlock]);

  const closeDialog = useCallback(() => {
    if (loading) return;
    setDialogOpen(false);
    setPassword("");
    setError(null);
  }, [loading]);

  return (
    <>
      {/* ── animated ring keyframes ── */}
      <style>{`
        @keyframes db-ring {
          0%   { transform: scale(1);   opacity: 0.5; }
          100% { transform: scale(2.2); opacity: 0;   }
        }
        .db-ring-1 { animation: db-ring 2.6s ease-out infinite; }
        .db-ring-2 { animation: db-ring 2.6s ease-out infinite 1.3s; }
      `}</style>

      {/* ── lock screen ── */}
      <div className="flex flex-col items-center justify-center min-h-[72vh] select-none">

        {/* icon with rings */}
        <div className="relative flex items-center justify-center mb-8" style={{ width: 96, height: 96 }}>
          <span
            className="db-ring-1 absolute inset-0 rounded-full border border-primary/25"
            style={{ borderRadius: "50%" }}
          />
          <span
            className="db-ring-2 absolute inset-0 rounded-full border border-primary/12"
            style={{ borderRadius: "50%" }}
          />
          <div
            className="w-20 h-20 rounded-full flex items-center justify-center"
            style={{
              background: "rgba(30,144,255,0.05)",
              border: "1.5px solid rgba(30,144,255,0.2)",
              boxShadow: "0 0 28px rgba(30,144,255,0.08), inset 0 0 16px rgba(30,144,255,0.03)",
            }}
          >
            <Lock className="w-8 h-8 text-primary" strokeWidth={1.8} />
          </div>
        </div>

        {/* label */}
        <p
          className="text-[10px] font-mono tracking-[0.38em] mb-3 uppercase"
          style={{ color: "rgba(30,144,255,0.55)" }}
        >
          ACCÈS RESTREINT
        </p>

        {/* headline */}
        <h2 className="text-[1.45rem] font-bold text-foreground mb-3 tracking-tight">
          Autorisation requise
        </h2>

        {/* body */}
        <p className="text-sm text-muted-foreground text-center max-w-[280px] leading-relaxed mb-8">
          Cette section est protégée.
          <br />
          Entrez le mot de passe administrateur
          <br />
          pour y accéder temporairement.
        </p>

        {/* unlock button */}
        <Button
          variant="outline"
          onClick={() => setDialogOpen(true)}
          className="gap-2 font-mono text-[11px] tracking-widest uppercase h-10 px-6"
          style={{
            borderColor: "rgba(30,144,255,0.28)",
            color: "rgba(30,144,255,0.9)",
          }}
        >
          <Key className="w-3.5 h-3.5" />
          Entrer le mot de passe
        </Button>
      </div>

      {/* ── password dialog ── */}
      <Dialog open={dialogOpen} onOpenChange={closeDialog}>
        <DialogContent className="sm:max-w-[360px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-[15px]">
              <Key className="w-4 h-4 text-primary" />
              Autorisation administrateur
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-3 pt-1 pb-2">
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">
                Mot de passe admin
              </Label>
              <div className="relative">
                <Input
                  type={showPwd ? "text" : "password"}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    setError(null);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !loading) handleConfirm();
                  }}
                  disabled={loading}
                  autoFocus
                  placeholder="••••••••"
                  className="pr-9"
                />
                <button
                  type="button"
                  onClick={() => setShowPwd((v) => !v)}
                  tabIndex={-1}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                >
                  {showPwd
                    ? <EyeOff className="w-3.5 h-3.5" />
                    : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            {error && (
              <Alert variant="destructive" className="py-2">
                <AlertDescription className="text-xs">{error}</AlertDescription>
              </Alert>
            )}
          </div>

          <DialogFooter className="gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={closeDialog}
              disabled={loading}
            >
              Annuler
            </Button>
            <Button
              size="sm"
              onClick={handleConfirm}
              disabled={loading || !password.trim()}
              className="gap-1.5"
            >
              {loading
                ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                : <LockOpen className="w-3.5 h-3.5" />}
              {loading ? "Vérification…" : "Confirmer"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ─── session badge ────────────────────────────────────────────────────────────

function SessionBadge({ remaining, onLock }: { remaining: number; onLock: () => void }) {
  return (
    <div
      className="flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-mono"
      style={{
        background: "rgba(30,144,255,0.07)",
        border: "1px solid rgba(30,144,255,0.2)",
        color: "rgba(30,144,255,0.85)",
      }}
    >
      <span
        className="w-1.5 h-1.5 rounded-full"
        style={{
          background: "#1e90ff",
          boxShadow: "0 0 4px rgba(30,144,255,0.8)",
          animation: "pulse 2s ease-in-out infinite",
        }}
      />
      {fmtMs(remaining)}
      <button
        type="button"
        onClick={onLock}
        title="Verrouiller"
        className="ml-0.5 opacity-40 hover:opacity-80 transition-opacity"
      >
        <X className="w-3 h-3" />
      </button>
    </div>
  );
}

// ─── main page ────────────────────────────────────────────────────────────────

// Module-scope constant — avoids re-creation on every render
const SYNC_SKIP = new Set(["fingerprints_json", "face_id", "qr_code_payload"]);

export default function LocalDbPage() {
  // ── lock state ──
  const [unlocked, setUnlocked] = useState(() => readUnlock().ok);
  const [remaining, setRemaining] = useState(() => readUnlock().rem);
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!unlocked) {
      if (tickRef.current) clearInterval(tickRef.current);
      return;
    }
    tickRef.current = setInterval(() => {
      const s = readUnlock();
      if (!s.ok) {
        setUnlocked(false);
        setRemaining(0);
      } else {
        setRemaining(s.rem);
      }
    }, 1000);
    return () => {
      if (tickRef.current) clearInterval(tickRef.current);
    };
  }, [unlocked]);

  const handleUnlock = useCallback(() => setUnlocked(true), []);
  const handleLock = useCallback(() => {
    sessionStorage.removeItem(UNLOCK_KEY);
    setUnlocked(false);
    setRemaining(0);
  }, []);

  // ── data state ──
  const [tab, setTab] = useState("sync");
  const [syncUsers, setSyncUsers] = useState<any[]>([]);
  const [syncLoading, setSyncLoading] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [tableName, setTableName] = useState("sync_users");
  const [rawRows, setRawRows] = useState<any[]>([]);
  const [rawCols, setRawCols] = useState<string[]>([]);
  const [rawLoading, setRawLoading] = useState(false);
  const [rawError, setRawError] = useState<string | null>(null);
  const [historyRows, setHistoryRows] = useState<any[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  // ── FK lookup context (loaded silently on unlock) ──
  const [fkCtx, setFkCtx] = useState<FkLookupContext>(EMPTY_FK_CONTEXT);
  const [modalState, setModalState] = useState<CellDetailModalState>(CLOSED_MODAL);

  const handleExpand = useCallback((title: string, content: React.ReactNode) => {
    setModalState({ open: true, title, content });
  }, []);

  const closeModal = useCallback(() => setModalState(CLOSED_MODAL), []);

  // Silently load FK lookup data when the page unlocks
  useEffect(() => {
    if (!unlocked) return;
    let cancelled = false;
    (async () => {
      try {
        const [usersRes, devicesRes] = await Promise.all([
          get<any>("/sync/cache/users", { limit: "5000" }),
          get<any>("/sync/cache/devices", { includeDoorPresets: "0" }),
        ]);

        if (cancelled) return;

        const users: any[] = usersRes?.users ?? [];
        const devices: any[] = devicesRes?.devices ?? [];

        const userById = new Map<number, Record<string, unknown>>();
        const userByCard = new Map<string, Record<string, unknown>>();
        users.forEach((u) => {
          const id = u.userId ?? u.user_id;
          if (id != null) userById.set(Number(id), u);
          const c1 = u.firstCardId ?? u.first_card_id;
          const c2 = u.secondCardId ?? u.second_card_id;
          if (c1) userByCard.set(String(c1), u);
          if (c2) userByCard.set(String(c2), u);
        });

        const deviceById = new Map<number, Record<string, unknown>>();
        devices.forEach((d) => {
          if (d.id != null) deviceById.set(Number(d.id), d);
        });

        setFkCtx({ userById, userByCard, deviceById, onExpand: handleExpand });
      } catch {
        // Best-effort — FK chips degrade to raw values silently
      }
    })();
    return () => { cancelled = true; };
  }, [unlocked, handleExpand]);

  const loadSync = useCallback(async () => {
    setSyncLoading(true);
    setSyncError(null);
    try {
      const res = await get<any>("/sync/cache/users", { limit: "5000" });
      setSyncUsers(res.users || []);
    } catch (e: any) {
      setSyncError(e?.message || String(e));
    } finally {
      setSyncLoading(false);
    }
  }, []);

  const loadRawTable = useCallback(async (table?: string) => {
    const t = table || tableName;
    setRawLoading(true);
    setRawError(null);
    try {
      const res = await get<any>(`/db/table/${t}`, { limit: "500" });
      setRawRows(res.rows || []);
      setRawCols(res.columns || []);
    } catch (e: any) {
      setRawError(e?.message || String(e));
      setRawRows([]);
      setRawCols([]);
    } finally {
      setRawLoading(false);
    }
  }, [tableName]);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const res = await get<any>("/db/access-history", { limit: "500" });
      setHistoryRows(res.records || []);
    } catch (e: any) {
      setHistoryError(e?.message || String(e));
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  const exportToExcel = useCallback((data: any[], filename: string) => {
    if (!data.length) return;
    const ws = XLSX.utils.json_to_sheet(data);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Data");
    XLSX.writeFile(wb, `${filename}-${new Date().toISOString().split("T")[0]}.xlsx`);
  }, []);

  const syncColumns = useMemo(
    () =>
      buildSmartColumns(
        syncUsers.length
          ? Object.keys(syncUsers[0]).filter((k) => !SYNC_SKIP.has(k))
          : [],
        syncUsers,
        { ...fkCtx, onExpand: handleExpand },
      ),
    [syncUsers, fkCtx, handleExpand],
  );

  const rawColumns = useMemo(
    () => buildSmartColumns(rawCols, rawRows, { ...fkCtx, onExpand: handleExpand }),
    [rawCols, rawRows, fkCtx, handleExpand],
  );

  const historyColumns = useMemo(
    () =>
      buildSmartColumns(
        historyRows.length ? Object.keys(historyRows[0]) : [],
        historyRows,
        { ...fkCtx, onExpand: handleExpand },
      ),
    [historyRows, fkCtx, handleExpand],
  );

  const TABLES = [
    "sync_users", "sync_devices", "sync_device_door_presets", "sync_memberships",
    "sync_infrastructures", "sync_gym_access_credentials",
    "fingerprints", "access_history", "auth_tokens", "sync_cache_meta",
  ];

  // ── render lock screen ──
  if (!unlocked) {
    return <LockScreen onUnlock={handleUnlock} />;
  }

  // ── render content ──
  return (
    <TooltipProvider>
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Database className="h-5 w-5 text-primary" />
          <h1 className="text-lg font-semibold">Base de données locale</h1>
        </div>
        <SessionBadge remaining={remaining} onLock={handleLock} />
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="sync">Cache Sync</TabsTrigger>
          <TabsTrigger value="history">Historique accès</TabsTrigger>
          <TabsTrigger value="raw">Table brute</TabsTrigger>
        </TabsList>

        {/* Sync cache tab */}
        <TabsContent value="sync" className="space-y-3">
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={loadSync} disabled={syncLoading}>
              {syncLoading
                ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                : <RefreshCw className="h-3.5 w-3.5" />}
              Charger
            </Button>
            {syncUsers.length > 0 && (
              <Button size="sm" variant="outline" onClick={() => exportToExcel(syncUsers, "sync-users")}>
                <Download className="h-3.5 w-3.5" /> Excel
              </Button>
            )}
            {syncUsers.length > 0 && (
              <Badge variant="secondary" className="text-xs">
                {syncUsers.length} utilisateurs
              </Badge>
            )}
          </div>
          {syncError && (
            <Alert variant="destructive">
              <AlertDescription>{syncError}</AlertDescription>
            </Alert>
          )}
          {syncUsers.length > 0 ? (
            <DataTable
              columns={syncColumns}
              data={syncUsers}
              searchKey="full_name"
              searchPlaceholder="Rechercher un utilisateur…"
              emptyMessage="Aucune donnée dans le cache sync."
            />
          ) : !syncLoading && (
            <p className="text-sm text-muted-foreground py-8 text-center">
              Cliquez sur « Charger » pour afficher le cache de synchronisation.
            </p>
          )}
        </TabsContent>

        {/* History tab */}
        <TabsContent value="history" className="space-y-3">
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={loadHistory} disabled={historyLoading}>
              {historyLoading
                ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                : <RefreshCw className="h-3.5 w-3.5" />}
              Charger
            </Button>
            {historyRows.length > 0 && (
              <Button size="sm" variant="outline" onClick={() => exportToExcel(historyRows, "access-history")}>
                <Download className="h-3.5 w-3.5" /> Excel
              </Button>
            )}
            <Badge variant="secondary" className="text-xs">
              {historyRows.length} entrées
            </Badge>
          </div>
          {historyError && (
            <Alert variant="destructive">
              <AlertDescription>{historyError}</AlertDescription>
            </Alert>
          )}
          {historyRows.length > 0 ? (
            <DataTable
              columns={historyColumns}
              data={historyRows}
              searchPlaceholder="Rechercher…"
              emptyMessage="Aucun historique d'accès."
            />
          ) : !historyLoading && (
            <p className="text-sm text-muted-foreground py-8 text-center">
              Cliquez sur « Charger » pour afficher l'historique d'accès.
            </p>
          )}
        </TabsContent>

        {/* Raw table tab */}
        <TabsContent value="raw" className="space-y-3">
          <div className="flex items-center gap-2 flex-wrap">
            <Select
              value={tableName}
              onValueChange={(v: string) => {
                setTableName(v);
                setRawRows([]);
                setRawCols([]);
              }}
            >
              <SelectTrigger className="w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TABLES.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}
              </SelectContent>
            </Select>
            <Button size="sm" variant="outline" onClick={() => loadRawTable()} disabled={rawLoading}>
              {rawLoading
                ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                : <RefreshCw className="h-3.5 w-3.5" />}
              Charger
            </Button>
            {rawRows.length > 0 && (
              <Button size="sm" variant="outline" onClick={() => exportToExcel(rawRows, tableName)}>
                <Download className="h-3.5 w-3.5" /> Excel
              </Button>
            )}
            <Badge variant="secondary" className="text-xs">
              {rawRows.length} lignes
            </Badge>
          </div>
          {rawError && (
            <Alert variant="destructive">
              <AlertDescription>{rawError}</AlertDescription>
            </Alert>
          )}
          {rawRows.length > 0 ? (
            <DataTable
              columns={rawColumns}
              data={rawRows}
              searchPlaceholder="Rechercher…"
              emptyMessage="Table vide."
            />
          ) : !rawLoading && (
            <p className="text-sm text-muted-foreground py-8 text-center">
              Sélectionnez une table et cliquez sur « Charger ».
            </p>
          )}
        </TabsContent>
      </Tabs>
      <CellDetailModal state={modalState} onClose={closeModal} />
    </div>
    </TooltipProvider>
  );
}

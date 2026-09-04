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
  Timer,
  AlertCircle,
} from "lucide-react";
import { usePageChrome } from "@/context/PageChromeContext";
import { cn } from "@/lib/utils";
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
  const [password, setPassword] = useState("");
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleConfirm = useCallback(async () => {
    if (!password.trim() || loading) return; // eslint-disable-line
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

  // Access v3, screen 07 — the only screen in the refonte WITHOUT a rail: when
  // there is exactly one thing to do, everything else disappears. The password
  // is entered inline rather than in a dialog (design's explicit change); the
  // auth call itself is untouched.
  return (
    <>
      <style>{`
        @keyframes db-ring {
          0%   { transform: scale(1);   opacity: .5; }
          100% { transform: scale(2.2); opacity: 0;  }
        }
        .db-ring-1 { animation: db-ring 2.8s ease-out infinite; }
        .db-ring-2 { animation: db-ring 2.8s ease-out infinite 1.4s; }
      `}</style>

      <div className="relative flex h-full min-h-0 select-none items-center justify-center overflow-hidden">
        <div className="relative flex w-[420px] flex-col items-center text-center">

          <div className="relative mb-[30px] flex h-[108px] w-[108px] items-center justify-center">
            <span className="db-ring-1 absolute h-24 w-24 rounded-full bg-primary/10" />
            <span className="db-ring-2 absolute h-24 w-24 rounded-full bg-primary/[0.08]" />
            <div className="relative flex h-[88px] w-[88px] items-center justify-center rounded-full border-[1.5px] border-primary/20 bg-card text-primary shadow-[0_8px_20px_rgba(226,32,63,0.10)]">
              <Lock className="h-[38px] w-[38px]" strokeWidth={1.6} />
            </div>
          </div>

          <p className="mb-3.5 font-mono text-[10px] font-bold uppercase tracking-[0.38em] text-primary">
            Accès restreint
          </p>
          <h2 className="mb-3 font-display text-[32px] font-extrabold leading-[1.1] tracking-[-0.03em] text-foreground">
            Autorisation requise
          </h2>
          <p className="mb-[30px] max-w-[330px] text-[14.5px] leading-[1.6] text-muted-foreground">
            Cette section contient les données brutes du club. Saisissez le mot de passe
            administrateur pour l'ouvrir.
          </p>

          <div className="flex w-[320px] flex-col gap-[11px]">
            <div className="relative">
              <Key className="pointer-events-none absolute left-[15px] top-1/2 h-[19px] w-[19px] -translate-y-1/2 text-muted-foreground" />
              <Input
                type={showPwd ? "text" : "password"}
                value={password}
                onChange={(e) => { setPassword(e.target.value); setError(null); }}
                onKeyDown={(e) => { if (e.key === "Enter" && !loading) handleConfirm(); }}
                disabled={loading}
                autoFocus
                placeholder="••••••••"
                className={cn(
                  "h-[46px] rounded-xl border-[1.5px] pl-[46px] pr-[42px] text-[15px] tracking-[0.1em]",
                  error ? "border-primary" : "border-border focus-visible:border-primary",
                )}
              />
              <button
                type="button"
                tabIndex={-1}
                onClick={() => setShowPwd((v) => !v)}
                className="absolute right-[15px] top-1/2 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground"
              >
                {showPwd ? <EyeOff className="h-[18px] w-[18px]" /> : <Eye className="h-[18px] w-[18px]" />}
              </button>
            </div>

            {error && (
              <div className="flex items-start gap-[9px] rounded-xl border border-primary/20 bg-primary/[0.05] px-[13px] py-2.5 text-left">
                <AlertCircle className="mt-px h-4 w-4 shrink-0 text-primary" />
                <span className="text-[12px] leading-[1.5] text-primary">{error}</span>
              </div>
            )}

            <Button
              onClick={handleConfirm}
              disabled={loading || !password.trim()}
              className="h-[46px] w-full justify-center gap-2 rounded-full text-[14px] font-bold shadow-[0_8px_20px_rgba(226,32,63,0.22)]"
            >
              {loading ? <Loader2 className="h-[18px] w-[18px] animate-spin" /> : <LockOpen className="h-[18px] w-[18px]" />}
              {loading ? "Vérification…" : "Déverrouiller"}
            </Button>
          </div>

          {/* The duration below is SESSION_MS, not the design's placeholder copy. */}
          <div className="mt-[26px] flex items-center gap-2">
            <Timer className="h-[15px] w-[15px] text-muted-foreground" />
            <span className="text-[11.5px] text-muted-foreground">
              La session se reverrouille automatiquement après {Math.round(SESSION_MS / 60000)} minutes
            </span>
          </div>
        </div>
      </div>
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
          // templates=0: this call only builds the FK chip maps (userId / card
          // numbers) and never reads fingerprints. Fetching the blobs made this
          // ~6s of pure disk I/O on the gym PC.
          get<any>("/sync/cache/users", { limit: "5000", templates: "0" }),
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

  // Rail table list with row counts — GET /api/v2/db/tables already returns
  // [{name, rowCount}] for every table in the SQLite file, so no count is
  // estimated here. Loaded once per unlock.
  const [tableStats, setTableStats] = useState<{ name: string; rowCount: number }[]>([]);
  useEffect(() => {
    if (!unlocked) return;
    let cancelled = false;
    void (async () => {
      try {
        const res = await get<{ tables?: { name: string; rowCount: number }[] }>("/db/tables");
        if (!cancelled) setTableStats(Array.isArray(res?.tables) ? res.tables : []);
      } catch { /* rail falls back to the static TABLES list without counts */ }
    })();
    return () => { cancelled = true; };
  }, [unlocked]);

  const countOf = useCallback(
    (name: string) => tableStats.find((t) => t.name === name)?.rowCount ?? null,
    [tableStats],
  );

  // Which dataset the current tab is showing, for the export action + card meta.
  const activeExport = tab === "sync"
    ? { rows: syncUsers, name: "sync-users" }
    : tab === "history"
      ? { rows: historyRows, name: "access-history" }
      : { rows: rawRows, name: tableName };

  const sessionPct = Math.max(0, Math.min(100, Math.round((remaining / SESSION_MS) * 100)));

  usePageChrome(() => ({
    fill: true,
    subtitle: unlocked ? (
      <span className="inline-flex h-[22px] items-center gap-1.5 rounded-lg bg-emerald-500/[0.055] px-2 text-[11px] font-bold text-emerald-700 dark:text-emerald-400">
        <LockOpen className="h-3 w-3" />Déverrouillée · {fmtMs(remaining)}
      </span>
    ) : (
      <span className="inline-flex h-[22px] items-center gap-1.5 rounded-lg bg-primary/[0.09] px-2 text-[11px] font-bold text-primary">
        <Lock className="h-3 w-3" />Verrouillée
      </span>
    ),
    actions: unlocked ? (
      <>
        <Button
          variant="outline"
          className="h-[30px] gap-1.5 rounded-[14px] px-[13px] text-[12px] font-semibold"
          disabled={activeExport.rows.length === 0}
          onClick={() => exportToExcel(activeExport.rows, activeExport.name)}
        >
          <Download className="h-[15px] w-[15px]" />Exporter en Excel
        </Button>
        <Button
          variant="outline"
          className="h-[30px] gap-1.5 rounded-[14px] px-[13px] text-[12px] font-semibold"
          onClick={handleLock}
        >
          <Lock className="h-[15px] w-[15px]" />Verrouiller
        </Button>
      </>
    ) : undefined,
    // Primitives only — see the note in UsersPage: a changing function
    // reference here re-runs the effect on every render and loops.
  }), [unlocked, remaining, tab, activeExport.rows.length, activeExport.name]);

  // ── render lock screen ──
  if (!unlocked) {
    return <LockScreen onUnlock={handleUnlock} />;
  }

  // ── render content ──
  return (
    <TooltipProvider>
    <div className="flex h-full min-h-0 gap-4">
      {/* ── Le sujet : la table, pleine hauteur ─────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col gap-[11px]">
      <Tabs value={tab} onValueChange={setTab} className="flex min-h-0 flex-1 flex-col gap-[11px]">
        <div className="flex flex-none items-center gap-[9px]">
          <TabsList className="h-[34px] rounded-xl bg-muted p-[3px]">
            <TabsTrigger value="sync" className="h-7 rounded-[9px] px-[13px] text-[12.5px] data-[state=active]:font-bold">Cache Sync</TabsTrigger>
            <TabsTrigger value="history" className="h-7 rounded-[9px] px-[13px] text-[12.5px] data-[state=active]:font-bold">Historique accès</TabsTrigger>
            <TabsTrigger value="raw" className="h-7 rounded-[9px] px-[13px] text-[12.5px] data-[state=active]:font-bold">Table brute</TabsTrigger>
          </TabsList>
          <span className="ml-auto inline-flex items-center gap-2 text-[11.5px] text-muted-foreground">
            <Database className="h-[15px] w-[15px]" />
            {activeExport.rows.length} ligne{activeExport.rows.length > 1 ? "s" : ""} chargée{activeExport.rows.length > 1 ? "s" : ""}
          </span>
        </div>

        {/* Sync cache tab */}
        <TabsContent value="sync" className="mt-0 flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto rounded-3xl bg-card p-5 shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
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
        <TabsContent value="history" className="mt-0 flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto rounded-3xl bg-card p-5 shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
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
        <TabsContent value="raw" className="mt-0 flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto rounded-3xl bg-card p-5 shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
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
      </div>

      {/* ── Le rail ─────────────────────────────────────────────────────── */}
      <div className="flex w-[330px] flex-none flex-col gap-[11px]">
        <div className="flex flex-none items-center gap-[9px]">
          <span className="inline-flex h-[22px] items-center gap-1.5 rounded-lg bg-primary/[0.08] px-[9px] text-[10.5px] font-bold uppercase tracking-[0.05em] text-primary">
            <Timer className="h-3 w-3" />Session
          </span>
        </div>

        {/* The countdown is the real sessionStorage lease (SESSION_MS), the same
            value that re-locks the page when it reaches zero. */}
        <div className="flex-none rounded-3xl bg-card px-5 py-[18px] shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          <div className="mb-[13px] flex items-center gap-[13px]">
            <span className="flex h-[42px] w-[42px] shrink-0 items-center justify-center rounded-[18px] bg-emerald-500/[0.055] text-emerald-700 dark:text-emerald-400">
              <LockOpen className="h-[21px] w-[21px]" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="num text-[20px] leading-none">{fmtMs(remaining)}</div>
              <div className="mt-1 text-[11.5px] text-muted-foreground">avant reverrouillage</div>
            </div>
          </div>
          <div className="mb-[13px] h-1.5 overflow-hidden rounded-full bg-muted">
            <div className="h-full rounded-full bg-emerald-500 transition-[width] duration-1000" style={{ width: `${sessionPct}%` }} />
          </div>
          <Button
            variant="outline"
            className="h-8 w-full justify-center gap-1.5 rounded-[14px] text-[12px] font-semibold"
            onClick={handleLock}
          >
            <Lock className="h-[15px] w-[15px]" />Verrouiller maintenant
          </Button>
        </div>

        <div className="mt-[3px] flex flex-none items-center gap-[9px]">
          <span className="inline-flex h-[22px] items-center gap-1.5 rounded-lg bg-muted px-[9px] text-[10.5px] font-bold uppercase tracking-[0.05em] text-muted-foreground">
            <Database className="h-3 w-3" />Tables
          </span>
          <span className="text-[11.5px] text-muted-foreground">{tableStats.length || TABLES.length}</span>
        </div>
        <div className="flex min-h-0 flex-1 flex-col gap-[3px] overflow-y-auto rounded-[18px] bg-card px-[18px] py-[11px] shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          {(tableStats.length ? tableStats.map((t) => t.name) : TABLES).map((name) => {
            const active = tab === "raw" && tableName === name;
            const c = countOf(name);
            return (
              <button
                key={name}
                onClick={() => { setTab("raw"); setTableName(name); void loadRawTable(name); }}
                className={cn(
                  "flex items-center justify-between gap-2.5 rounded-[10px] px-2.5 py-[7px] text-left transition-colors",
                  active ? "bg-foreground" : "hover:bg-muted",
                )}
              >
                <span className={cn("truncate font-mono text-[12px]", active ? "font-semibold text-background" : "text-muted-foreground")}>
                  {name}
                </span>
                {c != null && (
                  <span className={cn("shrink-0 font-mono text-[11px]", active ? "text-background/70" : "text-muted-foreground")}>
                    {c.toLocaleString("fr-FR")}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      <CellDetailModal state={modalState} onClose={closeModal} />
    </div>
    </TooltipProvider>
  );
}

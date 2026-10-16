import React, { useState, useCallback, useMemo, useEffect, useRef } from "react";
import { get, post } from "@/api/client";
import { DataTable } from "@/components/ui/data-table";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ActionButton } from "@/components/ui/action-button";
import { Chip } from "@/components/ui/chip";
import { LineTabs } from "@/components/ui/line-tabs";
import { ListRow, Note, PageGrid, Panel, PanelHeader, PanelList } from "@/components/ui/panel";
import {
  Database,
  Download,
  History,
  Loader2,
  RefreshCw,
  Lock,
  LockOpen,
  Eye,
  EyeOff,
  ScrollText,
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

/** 50 593 792 → « 48,2 Mo » (dbSizeBytes from GET /db/tables). */
function fmtSize(bytes: number | null): string {
  if (bytes == null || !Number.isFinite(bytes) || bytes <= 0) return "";
  const mo = bytes / (1024 * 1024);
  return mo >= 1 ? `${mo.toFixed(1).replace(".", ",")} Mo` : `${Math.max(1, Math.round(bytes / 1024))} Ko`;
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
        ? "Le serveur ne répond pas. Vérifiez votre connexion internet."
        : (e?.message ?? "Erreur d'authentification");
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [password, loading, onUnlock]);

  // Board S20: one card, one thing to do. The password is entered inline (no
  // dialog); the auth call itself is untouched.
  return (
    <PageGrid>
      <Panel className="col-span-12">
        <div className="flex flex-col items-center px-5 pb-[30px] pt-9 text-center">
          <span className="grid h-16 w-16 place-items-center rounded-full bg-primary/12 text-primary">
            <Lock className="h-[30px] w-[30px]" />
          </span>
          <div className="mt-3.5 text-[11.5px] font-bold uppercase tracking-[0.08em] text-muted-foreground">Accès restreint</div>
          <h2 className="mt-0.5 text-[19px] font-bold">Autorisation requise</h2>
          <p className="mt-1 max-w-[380px] text-[13.5px] leading-normal text-muted-foreground">
            Cette section contient les données brutes du club. Saisissez le mot de passe
            administrateur pour l'ouvrir.
          </p>

          <label htmlFor="localdb-pwd" className="mt-[18px] w-[320px] text-left text-[12.5px] font-semibold text-muted-foreground">
            Mot de passe administrateur
          </label>
          <div
            className={cn(
              "mt-1.5 flex h-[42px] w-[320px] items-center gap-2 rounded-lg border px-3 focus-within:border-primary",
              error ? "border-error" : "border-grey/32",
            )}
          >
            <Input
              id="localdb-pwd"
              type={showPwd ? "text" : "password"}
              value={password}
              onChange={(e) => { setPassword(e.target.value); setError(null); }}
              onKeyDown={(e) => { if (e.key === "Enter" && !loading) handleConfirm(); }}
              disabled={loading}
              autoFocus
              placeholder="••••••••"
              className="h-9 flex-1 rounded-none border-0 bg-transparent px-0 text-[15px] tracking-[0.2em] shadow-none focus-visible:ring-0"
            />
            <button
              type="button"
              tabIndex={-1}
              aria-label={showPwd ? "Masquer le mot de passe" : "Afficher le mot de passe"}
              onClick={() => setShowPwd((v) => !v)}
              className="grid place-items-center text-muted-foreground transition-colors hover:text-foreground"
            >
              {showPwd ? <EyeOff className="h-[18px] w-[18px]" /> : <Eye className="h-[18px] w-[18px]" />}
            </button>
          </div>

          {error && (
            <Note tone="error" className="mt-2.5 flex w-[320px] items-start gap-2 text-left text-[12.5px]">
              <AlertCircle className="mt-px h-4 w-4 shrink-0" />
              <span>{error}</span>
            </Note>
          )}

          <ActionButton
            kind="dark"
            className="mt-3.5 h-10 w-[320px]"
            icon={loading ? Loader2 : LockOpen}
            spin={loading}
            onClick={handleConfirm}
            disabled={loading || !password.trim()}
          >
            {loading ? "Vérification…" : "Déverrouiller"}
          </ActionButton>

          {/* The duration below is SESSION_MS — a fixed lease from the unlock, not inactivity. */}
          <div className="mt-3 flex items-center gap-2 text-[12.5px] text-muted-foreground">
            <Timer className="h-[15px] w-[15px] shrink-0" />
            <span>
              Vérifié en ligne par le serveur MonClub (Internet requis). La session se reverrouille
              automatiquement {Math.round(SESSION_MS / 60000)} minutes après l'ouverture.
            </span>
          </div>
        </div>
      </Panel>
    </PageGrid>
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

  // Show the real lease at once (the 1 s tick would first show « 0:00 »).
  const handleUnlock = useCallback(() => { setUnlocked(true); setRemaining(readUnlock().rem); }, []);
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
    "fingerprints", "access_history",
  ];

  // Rail table list with row counts — GET /api/v2/db/tables already returns
  // [{name, rowCount}] for every table in the SQLite file, so no count is
  // estimated here. Loaded once per unlock.
  const [tableStats, setTableStats] = useState<{ name: string; rowCount: number }[]>([]);
  const [dbSizeBytes, setDbSizeBytes] = useState<number | null>(null);
  useEffect(() => {
    if (!unlocked) return;
    let cancelled = false;
    void (async () => {
      try {
        const res = await get<{ tables?: { name: string; rowCount: number }[]; dbSizeBytes?: number }>("/db/tables");
        if (!cancelled) {
          setTableStats(Array.isArray(res?.tables) ? res.tables : []);
          // Same response: the SQLite file size, shown in the header.
          setDbSizeBytes(typeof res?.dbSizeBytes === "number" ? res.dbSizeBytes : null);
        }
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

  const sizeLabel = fmtSize(dbSizeBytes);

  usePageChrome(() => ({
    fill: true,
    subtitle: unlocked ? (
      <span className="inline-flex items-center gap-2">
        <Chip tone="success" icon={LockOpen}>Déverrouillée</Chip>
        <span>se reverrouille dans {fmtMs(remaining)}{sizeLabel ? ` · ${sizeLabel}` : ""}</span>
      </span>
    ) : (
      <span className="inline-flex items-center gap-2">
        <Chip tone="grey" icon={Lock}>Verrouillée</Chip>
        <span>SQLite de ce poste, lecture seule</span>
      </span>
    ),
    actions: unlocked ? (
      <>
        <ActionButton
          kind="outline"
          icon={Download}
          disabled={activeExport.rows.length === 0}
          onClick={() => exportToExcel(activeExport.rows, activeExport.name)}
        >
          Exporter en Excel
        </ActionButton>
        <ActionButton kind="dark" icon={Lock} onClick={handleLock}>Verrouiller</ActionButton>
      </>
    ) : undefined,
    // Primitives only — see the note in UsersPage: a changing function
    // reference here re-runs the effect on every render and loops.
  }), [unlocked, remaining, tab, activeExport.rows.length, activeExport.name, sizeLabel]);

  // ── render lock screen ──
  if (!unlocked) {
    return <LockScreen onUnlock={handleUnlock} />;
  }

  const loadedBadge = (n: number, word: string) => (
    <Chip tone="grey">{n.toLocaleString("fr-FR")} {word}</Chip>
  );

  // ── render content ──
  return (
    <TooltipProvider>
    <div className="flex h-full min-h-0 flex-col gap-[18px]">
      <LineTabs
        className="-mt-1 flex-none"
        value={tab}
        onChange={setTab}
        items={[
          { value: "sync", label: "Cache sync", icon: Database },
          { value: "history", label: "Historique accès", icon: History },
          { value: "raw", label: "Table brute", icon: ScrollText },
        ]}
      />

      <div className="grid min-h-0 flex-1 grid-cols-12 gap-[18px]">
        {/* ── Le sujet : la table ─────────────────────────────────────────── */}
        <Panel className="col-span-8 flex min-h-0 flex-col">
          {tab === "sync" && (
            <>
              <PanelHeader
                title="Cache de synchronisation"
                sub={`sync_users${countOf("sync_users") != null ? ` · ${countOf("sync_users")!.toLocaleString("fr-FR")} lignes` : ""} (un abonnement par ligne)`}
                className="flex-none"
              >
                {syncUsers.length > 0 && loadedBadge(syncUsers.length, "lignes chargées")}
                <ActionButton kind="outline" size="md" icon={syncLoading ? Loader2 : RefreshCw} spin={syncLoading} onClick={loadSync} disabled={syncLoading}>
                  Charger
                </ActionButton>
                {syncUsers.length > 0 && (
                  <ActionButton kind="outline" size="md" icon={Download} onClick={() => exportToExcel(syncUsers, "sync-users")}>Excel</ActionButton>
                )}
              </PanelHeader>
              <div className="min-h-0 flex-1 overflow-y-auto px-[18px] pb-4 pt-3">
                {syncError && <Note tone="error" className="mb-3">{syncError}</Note>}
                {syncUsers.length > 0 ? (
                  <DataTable
                    columns={syncColumns}
                    data={syncUsers}
                    searchKey="full_name"
                    searchPlaceholder="Rechercher un utilisateur…"
                    emptyMessage="Aucune donnée dans le cache sync."
                  />
                ) : !syncLoading && (
                  <p className="py-8 text-center text-[13.5px] text-muted-foreground">
                    Cliquez sur « Charger » pour afficher le cache de synchronisation.
                  </p>
                )}
              </div>
            </>
          )}

          {tab === "history" && (
            <>
              <PanelHeader title="Historique accès" sub="access_history · passages enregistrés sur ce poste (500 derniers)" className="flex-none">
                {loadedBadge(historyRows.length, "entrées")}
                <ActionButton kind="outline" size="md" icon={historyLoading ? Loader2 : RefreshCw} spin={historyLoading} onClick={loadHistory} disabled={historyLoading}>
                  Charger
                </ActionButton>
                {historyRows.length > 0 && (
                  <ActionButton kind="outline" size="md" icon={Download} onClick={() => exportToExcel(historyRows, "access-history")}>Excel</ActionButton>
                )}
              </PanelHeader>
              <div className="min-h-0 flex-1 overflow-y-auto px-[18px] pb-4 pt-3">
                {historyError && <Note tone="error" className="mb-3">{historyError}</Note>}
                {historyRows.length > 0 ? (
                  <DataTable
                    columns={historyColumns}
                    data={historyRows}
                    searchPlaceholder="Rechercher…"
                    emptyMessage="Aucun historique d'accès."
                  />
                ) : !historyLoading && (
                  <p className="py-8 text-center text-[13.5px] text-muted-foreground">
                    Cliquez sur « Charger » pour afficher l'historique d'accès.
                  </p>
                )}
              </div>
            </>
          )}

          {tab === "raw" && (
            <>
              <PanelHeader title={tableName} sub="Lecture seule · 500 lignes max" className="flex-none">
                {loadedBadge(rawRows.length, "lignes")}
                <Select
                  value={tableName}
                  onValueChange={(v: string) => {
                    setTableName(v);
                    setRawRows([]);
                    setRawCols([]);
                  }}
                >
                  <SelectTrigger aria-label="Changer de table" className="h-8 w-56 rounded-lg border-grey/32 bg-card font-mono text-[13px] shadow-none">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {/* Once /db/tables answered, only list the curated tables that really exist. */}
                    {(tableStats.length ? TABLES.filter((t) => tableStats.some((s) => s.name === t)) : TABLES)
                      .map((t) => <SelectItem key={t} value={t} className="font-mono">{t}</SelectItem>)}
                  </SelectContent>
                </Select>
                <ActionButton kind="outline" size="md" icon={rawLoading ? Loader2 : RefreshCw} spin={rawLoading} onClick={() => loadRawTable()} disabled={rawLoading}>
                  Charger
                </ActionButton>
                {rawRows.length > 0 && (
                  <ActionButton kind="outline" size="md" icon={Download} onClick={() => exportToExcel(rawRows, tableName)}>Excel</ActionButton>
                )}
              </PanelHeader>
              <div className="min-h-0 flex-1 overflow-y-auto px-[18px] pb-4 pt-3">
                {rawError && <Note tone="error" className="mb-3">{rawError}</Note>}
                {rawRows.length > 0 ? (
                  <DataTable
                    columns={rawColumns}
                    data={rawRows}
                    searchPlaceholder="Rechercher…"
                    emptyMessage="Table vide."
                  />
                ) : !rawLoading && (
                  <p className="py-8 text-center text-[13.5px] text-muted-foreground">
                    Sélectionnez une table et cliquez sur « Charger ».
                  </p>
                )}
              </div>
            </>
          )}
        </Panel>

        {/* ── Le rail ─────────────────────────────────────────────────────── */}
        <div className="col-span-4 flex min-h-0 flex-col gap-[18px]">
          {/* The countdown is the real sessionStorage lease (SESSION_MS), the same
              value that re-locks the page when it reaches zero. */}
          <Panel className="flex-none">
            <PanelHeader title="Session" />
            <PanelList>
              <ListRow
                icon={Timer}
                tone="warning"
                title={`${fmtMs(remaining)} avant reverrouillage`}
                sub="Compte à rebours depuis l'ouverture"
                bar={sessionPct}
                barTone="warning"
                actions={<ActionButton kind="outline" size="sm" icon={Lock} onClick={handleLock}>Verrouiller maintenant</ActionButton>}
              />
            </PanelList>
          </Panel>

          <Panel className="flex min-h-0 flex-1 flex-col">
            <PanelHeader
              title={`Tables · ${tableStats.length || TABLES.length}`}
              sub="Toutes les tables SQLite de ce poste"
              className="flex-none"
            />
            <div className="min-h-0 flex-1 overflow-y-auto px-[18px] pb-3.5 pt-2.5">
              {(tableStats.length ? tableStats.map((t) => t.name) : TABLES).map((name) => {
                const active = tab === "raw" && tableName === name;
                const c = countOf(name);
                return (
                  <button
                    key={name}
                    type="button"
                    aria-pressed={active}
                    onClick={() => { setTab("raw"); setTableName(name); void loadRawTable(name); }}
                    className={cn(
                      "flex w-full cursor-pointer items-center justify-between gap-2.5 rounded-lg px-2.5 py-[7px] text-left transition-colors",
                      active ? "bg-primary/8 outline outline-1 outline-primary/32" : "hover:bg-muted",
                    )}
                  >
                    <span className={cn("truncate font-mono text-[13px]", active ? "font-semibold text-foreground" : "text-foreground")}>
                      {name}
                    </span>
                    {c != null && (
                      <span className="shrink-0 font-mono text-[12.5px] font-bold text-foreground">
                        {c.toLocaleString("fr-FR")}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </Panel>
        </div>
      </div>

      <CellDetailModal state={modalState} onClose={closeModal} />
    </div>
    </TooltipProvider>
  );
}

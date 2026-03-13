import { useState, useCallback, useMemo } from "react";
import { get } from "@/api/client";
import { type ColumnDef, DataTable } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Database, Download, Loader2, RefreshCw } from "lucide-react";
import * as XLSX from "xlsx";

export default function LocalDbPage() {
  const [tab, setTab] = useState("sync");
  // Sync cache (uses /sync/cache/users)
  const [syncUsers, setSyncUsers] = useState<any[]>([]);
  const [syncLoading, setSyncLoading] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  // Raw table
  const [tableName, setTableName] = useState("sync_users");
  const [rawRows, setRawRows] = useState<any[]>([]);
  const [rawCols, setRawCols] = useState<string[]>([]);
  const [rawLoading, setRawLoading] = useState(false);
  const [rawError, setRawError] = useState<string | null>(null);
  // History (uses /db/access-history)
  const [historyRows, setHistoryRows] = useState<any[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  const loadSync = useCallback(async () => {
    setSyncLoading(true); setSyncError(null);
    try {
      const res = await get<any>("/sync/cache/users", { limit: "5000" });
      setSyncUsers(res.users || []);
    } catch (e: any) {
      setSyncError(e?.message || String(e));
    } finally { setSyncLoading(false); }
  }, []);

  const loadRawTable = useCallback(async (table?: string) => {
    const t = table || tableName;
    setRawLoading(true); setRawError(null);
    try {
      const res = await get<any>(`/db/table/${t}`, { limit: "500" });
      setRawRows(res.rows || []); setRawCols(res.columns || []);
    } catch (e: any) {
      setRawError(e?.message || String(e)); setRawRows([]); setRawCols([]);
    } finally { setRawLoading(false); }
  }, [tableName]);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true); setHistoryError(null);
    try {
      const res = await get<any>("/db/access-history", { limit: "500" });
      setHistoryRows(res.records || []);
    } catch (e: any) {
      setHistoryError(e?.message || String(e));
    } finally { setHistoryLoading(false); }
  }, []);

  const exportToExcel = useCallback((data: any[], filename: string) => {
    if (!data.length) return;
    const ws = XLSX.utils.json_to_sheet(data);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Data");
    XLSX.writeFile(wb, `${filename}-${new Date().toISOString().split("T")[0]}.xlsx`);
  }, []);

  // Dynamic columns for sync users
  const syncColumns = useMemo<ColumnDef<any, any>[]>(() => {
    if (!syncUsers.length) return [];
    const skipKeys = new Set(["fingerprints_json", "face_id", "qr_code_payload"]);
    return Object.keys(syncUsers[0]).filter((k) => !skipKeys.has(k)).map((key) => ({
      accessorKey: key,
      header: key.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase()),
      cell: ({ row }: any) => {
        const v = row.original[key];
        if (v == null || v === "") return <span className="text-muted-foreground">—</span>;
        const s = String(v);
        return <span className="text-xs">{s.length > 60 ? s.substring(0, 60) + "…" : s}</span>;
      },
    }));
  }, [syncUsers]);

  // Dynamic columns for raw table
  const rawColumns = useMemo<ColumnDef<any, any>[]>(() => {
    return rawCols.map((col) => ({
      accessorKey: col, header: col,
      cell: ({ row }: any) => {
        const v = row.original[col];
        if (v == null || v === "") return <span className="text-muted-foreground">—</span>;
        const s = String(v);
        return <span className="text-xs">{s.length > 80 ? s.substring(0, 80) + "…" : s}</span>;
      },
    }));
  }, [rawCols]);

  // History columns
  const historyColumns = useMemo<ColumnDef<any, any>[]>(() => {
    if (!historyRows.length) return [];
    return Object.keys(historyRows[0]).map((key) => ({
      accessorKey: key,
      header: key.replace(/([A-Z])/g, " $1").replace(/^./, (s: string) => s.toUpperCase()),
      cell: ({ row }: any) => {
        const v = row.original[key];
        if (v == null || v === "") return <span className="text-muted-foreground">—</span>;
        if (key === "allowed") return <Badge variant={v ? "success" : "destructive"} className="text-[10px]">{v ? "Oui" : "Non"}</Badge>;
        return <span className="text-xs">{String(v)}</span>;
      },
    }));
  }, [historyRows]);

  const TABLES = [
    "sync_users", "sync_devices", "sync_device_door_presets", "sync_memberships",
    "sync_infrastructures", "sync_gym_access_credentials",
    "fingerprints", "access_history", "auth_tokens", "sync_cache_meta",
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Database className="h-5 w-5 text-primary" />
        <h1 className="text-lg font-semibold">Base de données locale</h1>
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
              {syncLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />} Charger
            </Button>
            {syncUsers.length > 0 && (
              <Button size="sm" variant="outline" onClick={() => exportToExcel(syncUsers, "sync-users")}>
                <Download className="h-3.5 w-3.5" /> Excel
              </Button>
            )}
            {syncUsers.length > 0 && <Badge variant="secondary" className="text-xs">{syncUsers.length} utilisateurs</Badge>}
          </div>
          {syncError && <Alert variant="destructive"><AlertDescription>{syncError}</AlertDescription></Alert>}
          {syncUsers.length > 0 ? (
            <DataTable columns={syncColumns} data={syncUsers} searchKey="full_name" searchPlaceholder="Rechercher un utilisateur…"
              emptyMessage="Aucune donnée dans le cache sync." />
          ) : !syncLoading && (
            <p className="text-sm text-muted-foreground py-8 text-center">Cliquez sur « Charger » pour afficher le cache de synchronisation.</p>
          )}
        </TabsContent>

        {/* History tab */}
        <TabsContent value="history" className="space-y-3">
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={loadHistory} disabled={historyLoading}>
              {historyLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />} Charger
            </Button>
            {historyRows.length > 0 && (
              <Button size="sm" variant="outline" onClick={() => exportToExcel(historyRows, "access-history")}>
                <Download className="h-3.5 w-3.5" /> Excel
              </Button>
            )}
            <Badge variant="secondary" className="text-xs">{historyRows.length} entrées</Badge>
          </div>
          {historyError && <Alert variant="destructive"><AlertDescription>{historyError}</AlertDescription></Alert>}
          {historyRows.length > 0 ? (
            <DataTable columns={historyColumns} data={historyRows} searchPlaceholder="Rechercher…"
              emptyMessage="Aucun historique d'accès." />
          ) : !historyLoading && (
            <p className="text-sm text-muted-foreground py-8 text-center">Cliquez sur « Charger » pour afficher l'historique d'accès.</p>
          )}
        </TabsContent>

        {/* Raw table tab */}
        <TabsContent value="raw" className="space-y-3">
          <div className="flex items-center gap-2 flex-wrap">
            <Select value={tableName} onValueChange={(v: string) => { setTableName(v); setRawRows([]); setRawCols([]); }}>
              <SelectTrigger className="w-56"><SelectValue /></SelectTrigger>
              <SelectContent>
                {TABLES.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}
              </SelectContent>
            </Select>
            <Button size="sm" variant="outline" onClick={() => loadRawTable()} disabled={rawLoading}>
              {rawLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />} Charger
            </Button>
            {rawRows.length > 0 && (
              <Button size="sm" variant="outline" onClick={() => exportToExcel(rawRows, tableName)}>
                <Download className="h-3.5 w-3.5" /> Excel
              </Button>
            )}
            <Badge variant="secondary" className="text-xs">{rawRows.length} lignes</Badge>
          </div>
          {rawError && <Alert variant="destructive"><AlertDescription>{rawError}</AlertDescription></Alert>}
          {rawRows.length > 0 ? (
            <DataTable columns={rawColumns} data={rawRows} searchPlaceholder="Rechercher…"
              emptyMessage="Table vide." />
          ) : !rawLoading && (
            <p className="text-sm text-muted-foreground py-8 text-center">Sélectionnez une table et cliquez sur « Charger ».</p>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

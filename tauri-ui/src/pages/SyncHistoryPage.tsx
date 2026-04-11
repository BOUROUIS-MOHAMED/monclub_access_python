import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, Eye, Loader2, RefreshCw } from "lucide-react";

import { get } from "@/api/client";
import type { SyncRunHistoryResponse, SyncRunHistoryRow } from "@/api/types";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? value : dt.toLocaleString("fr-FR");
}

function formatDuration(ms: number | null | undefined): string {
  const value = Number(ms || 0);
  if (!value) return "—";
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

function parseJsonBlock(value: string | null | undefined): string {
  if (!value) return "—";
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

function statusVariant(status: string) {
  switch (String(status || "").toUpperCase()) {
    case "SUCCESS":
      return "success" as const;
    case "PARTIAL":
      return "warning" as const;
    case "FAILED":
      return "destructive" as const;
    default:
      return "outline" as const;
  }
}

function StatsCard({ label, value }: { label: string; value: number }) {
  return (
    <Card className="py-4">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm text-muted-foreground">{label}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold">{value}</div>
      </CardContent>
    </Card>
  );
}

export default function SyncHistoryPage() {
  const [rows, setRows] = useState<SyncRunHistoryRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("__all");
  const [runTypeFilter, setRunTypeFilter] = useState("__all");
  const [detailLoading, setDetailLoading] = useState(false);
  const [selectedRun, setSelectedRun] = useState<SyncRunHistoryRow | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string> = { page: "0", size: "100" };
      if (statusFilter !== "__all") params.status = statusFilter;
      if (runTypeFilter !== "__all") params.runType = runTypeFilter;
      const res = await get<SyncRunHistoryResponse>("/sync-history", params);
      setRows(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [runTypeFilter, statusFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const stats = useMemo(() => {
    return rows.reduce(
      (acc, row) => {
        const status = String(row.status || "").toUpperCase();
        if (status === "SUCCESS") acc.success += 1;
        else if (status === "PARTIAL") acc.partial += 1;
        else if (status === "FAILED") acc.failed += 1;
        return acc;
      },
      { success: 0, partial: 0, failed: 0 },
    );
  }, [rows]);

  const openDetail = useCallback(async (id: number) => {
    setDetailLoading(true);
    try {
      const res = await get<{ ok: boolean; item: SyncRunHistoryRow }>(`/sync-history/${id}`);
      setSelectedRun(res.item);
    } catch (err) {
      setError(String(err));
    } finally {
      setDetailLoading(false);
    }
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <Activity className="h-5 w-5 text-primary" />
          <h1 className="text-lg font-semibold">Historique sync</h1>
          <Badge variant="secondary" className="text-xs">{total}</Badge>
        </div>
        <div className="flex items-center gap-2">
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-[170px]">
              <SelectValue placeholder="Statut" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all">Tous les statuts</SelectItem>
              <SelectItem value="SUCCESS">SUCCESS</SelectItem>
              <SelectItem value="PARTIAL">PARTIAL</SelectItem>
              <SelectItem value="FAILED">FAILED</SelectItem>
              <SelectItem value="IN_PROGRESS">IN_PROGRESS</SelectItem>
            </SelectContent>
          </Select>
          <Select value={runTypeFilter} onValueChange={setRunTypeFilter}>
            <SelectTrigger className="w-[170px]">
              <SelectValue placeholder="Type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all">Tous les types</SelectItem>
              <SelectItem value="PERIODIC">PERIODIC</SelectItem>
              <SelectItem value="TRIGGERED">TRIGGERED</SelectItem>
              <SelectItem value="HARD_RESET">HARD_RESET</SelectItem>
            </SelectContent>
          </Select>
          <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
            Recharger
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatsCard label="Runs chargés" value={rows.length} />
        <StatsCard label="SUCCESS" value={stats.success} />
        <StatsCard label="PARTIAL" value={stats.partial} />
        <StatsCard label="FAILED" value={stats.failed} />
      </div>

      <Card className="py-4">
        <CardHeader>
          <CardTitle className="text-sm">Synchronisations récentes</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="py-10 flex justify-center">
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
            </div>
          ) : (
            <div className="rounded-md border overflow-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Déclenché le</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Statut</TableHead>
                    <TableHead>Membres</TableHead>
                    <TableHead>Appareils</TableHead>
                    <TableHead>Durée</TableHead>
                    <TableHead className="text-right">Détails</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.length > 0 ? rows.map((row) => (
                    <TableRow key={row.id}>
                      <TableCell className="text-xs whitespace-nowrap">{formatDate(row.created_at)}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="font-mono text-[10px]">{row.trigger_source}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">{row.run_type}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(row.status)}>{row.status}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">
                        {row.members_changed} / {row.members_total}
                      </TableCell>
                      <TableCell className="text-xs">{row.devices_synced}</TableCell>
                      <TableCell className="text-xs">{formatDuration(row.duration_ms)}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="ghost"
                          className="gap-1.5"
                          onClick={() => void openDetail(row.id)}
                        >
                          <Eye className="h-4 w-4" />
                          Voir
                        </Button>
                      </TableCell>
                    </TableRow>
                  )) : (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center py-10 text-sm text-muted-foreground">
                        Aucun run trouvé pour les filtres actuels.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={!!selectedRun || detailLoading} onOpenChange={(open) => { if (!open) setSelectedRun(null); }}>
        <DialogContent className="max-w-4xl max-h-[85vh] overflow-auto">
          <DialogHeader>
            <DialogTitle>Run de synchronisation</DialogTitle>
          </DialogHeader>
          {detailLoading && !selectedRun ? (
            <div className="py-10 flex justify-center">
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
            </div>
          ) : selectedRun ? (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <Card className="py-4">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Déclenchement</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1 text-sm">
                    <div>Source: <span className="font-mono">{selectedRun.trigger_source}</span></div>
                    <div>Type: <span className="font-mono">{selectedRun.run_type}</span></div>
                    <div>Date: <span className="font-mono text-xs">{formatDate(selectedRun.created_at)}</span></div>
                  </CardContent>
                </Card>
                <Card className="py-4">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Résultat</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1 text-sm">
                    <div>Statut: <Badge variant={statusVariant(selectedRun.status)}>{selectedRun.status}</Badge></div>
                    <div>Durée: <span className="font-mono">{formatDuration(selectedRun.duration_ms)}</span></div>
                    <div>Erreur: <span className="font-mono text-xs">{selectedRun.error_message || "—"}</span></div>
                  </CardContent>
                </Card>
                <Card className="py-4">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Volumes</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1 text-sm">
                    <div>Membres total: <span className="font-mono">{selectedRun.members_total}</span></div>
                    <div>Membres changés: <span className="font-mono">{selectedRun.members_changed}</span></div>
                    <div>Appareils dispatchés: <span className="font-mono">{selectedRun.devices_synced}</span></div>
                  </CardContent>
                </Card>
              </div>

              <Card className="py-4">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Trigger hint</CardTitle>
                </CardHeader>
                <CardContent>
                  <pre className="rounded-md bg-muted p-3 text-xs whitespace-pre-wrap break-all">
                    {parseJsonBlock(selectedRun.trigger_hint)}
                  </pre>
                </CardContent>
              </Card>

              <Card className="py-4">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Résumé brut</CardTitle>
                </CardHeader>
                <CardContent>
                  <pre className="rounded-md bg-muted p-3 text-xs whitespace-pre-wrap break-all">
                    {parseJsonBlock(selectedRun.raw_response)}
                  </pre>
                </CardContent>
              </Card>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}

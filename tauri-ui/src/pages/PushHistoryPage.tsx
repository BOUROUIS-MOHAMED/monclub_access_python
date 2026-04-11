import { useCallback, useEffect, useMemo, useState } from "react";
import { Eye, Loader2, RefreshCw, Send } from "lucide-react";

import { get } from "@/api/client";
import type {
  PushBatchHistoryResponse,
  PushBatchHistoryRow,
  PushBatchPinsResponse,
  PushPinHistoryRow,
} from "@/api/types";
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
import { Input } from "@/components/ui/input";
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

export default function PushHistoryPage() {
  const [rows, setRows] = useState<PushBatchHistoryRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("__all");
  const [deviceIdFilter, setDeviceIdFilter] = useState("");
  const [detailLoading, setDetailLoading] = useState(false);
  const [selectedBatch, setSelectedBatch] = useState<PushBatchHistoryRow | null>(null);
  const [selectedPins, setSelectedPins] = useState<PushPinHistoryRow[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string> = { page: "0", size: "100" };
      if (statusFilter !== "__all") params.status = statusFilter;
      if (deviceIdFilter.trim()) params.deviceId = deviceIdFilter.trim();
      const res = await get<PushBatchHistoryResponse>("/push-history", params);
      setRows(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [deviceIdFilter, statusFilter]);

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
      { success: 0, partial: 0, failed: 0, pinsFailed: 0 },
    );
  }, [rows]);

  const pinsFailed = useMemo(
    () => rows.reduce((sum, row) => sum + Number(row.pins_failed || 0), 0),
    [rows],
  );

  const openDetail = useCallback(async (batchId: number) => {
    setDetailLoading(true);
    try {
      const res = await get<PushBatchPinsResponse>(`/push-history/${batchId}/pins`);
      setSelectedBatch(res.batch);
      setSelectedPins(res.pins || []);
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
          <Send className="h-5 w-5 text-primary" />
          <h1 className="text-lg font-semibold">Historique push</h1>
          <Badge variant="secondary" className="text-xs">{total}</Badge>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Input
            value={deviceIdFilter}
            onChange={(event) => setDeviceIdFilter(event.target.value)}
            placeholder="Filtrer par deviceId"
            className="w-[170px]"
          />
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
        <StatsCard label="Batches chargés" value={rows.length} />
        <StatsCard label="SUCCESS" value={stats.success} />
        <StatsCard label="PARTIAL" value={stats.partial} />
        <StatsCard label="Pins en échec" value={pinsFailed} />
      </div>

      <Card className="py-4">
        <CardHeader>
          <CardTitle className="text-sm">Pushs récents vers les appareils</CardTitle>
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
                    <TableHead>Date</TableHead>
                    <TableHead>Appareil</TableHead>
                    <TableHead>Sync run</TableHead>
                    <TableHead>Policy</TableHead>
                    <TableHead>Statut</TableHead>
                    <TableHead>Pins</TableHead>
                    <TableHead>Durée</TableHead>
                    <TableHead className="text-right">Détails</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.length > 0 ? rows.map((row) => (
                    <TableRow key={row.id}>
                      <TableCell className="text-xs whitespace-nowrap">{formatDate(row.created_at)}</TableCell>
                      <TableCell>
                        <div className="flex flex-col">
                          <span className="font-medium">{row.device_name}</span>
                          <span className="text-xs text-muted-foreground font-mono">deviceId={row.device_id}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs font-mono">{row.sync_run_id ?? "—"}</TableCell>
                      <TableCell className="text-xs">{row.policy}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(row.status)}>{row.status}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">
                        {row.pins_success}/{row.pins_attempted}
                        {row.pins_failed > 0 ? <span className="text-destructive"> ({row.pins_failed} KO)</span> : null}
                      </TableCell>
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
                        Aucun batch trouvé pour les filtres actuels.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog
        open={!!selectedBatch || detailLoading}
        onOpenChange={(open) => {
          if (!open) {
            setSelectedBatch(null);
            setSelectedPins([]);
          }
        }}
      >
        <DialogContent className="max-w-5xl max-h-[85vh] overflow-auto">
          <DialogHeader>
            <DialogTitle>Détail du batch push</DialogTitle>
          </DialogHeader>
          {detailLoading && !selectedBatch ? (
            <div className="py-10 flex justify-center">
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
            </div>
          ) : selectedBatch ? (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                <StatsCard label="Pins tentés" value={selectedBatch.pins_attempted} />
                <StatsCard label="Pins OK" value={selectedBatch.pins_success} />
                <StatsCard label="Pins KO" value={selectedBatch.pins_failed} />
                <Card className="py-4">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm text-muted-foreground">Statut</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <Badge variant={statusVariant(selectedBatch.status)}>{selectedBatch.status}</Badge>
                    <div className="text-xs text-muted-foreground">
                      {selectedBatch.device_name} · {formatDuration(selectedBatch.duration_ms)}
                    </div>
                  </CardContent>
                </Card>
              </div>

              {selectedBatch.error_message && (
                <Alert variant="warning">
                  <AlertDescription>{selectedBatch.error_message}</AlertDescription>
                </Alert>
              )}

              <div className="rounded-md border overflow-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>PIN</TableHead>
                      <TableHead>Nom</TableHead>
                      <TableHead>Opération</TableHead>
                      <TableHead>Statut</TableHead>
                      <TableHead>Durée</TableHead>
                      <TableHead>Erreur</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {selectedPins.length > 0 ? selectedPins.map((pin) => (
                      <TableRow key={pin.id}>
                        <TableCell className="font-mono text-xs">{pin.pin}</TableCell>
                        <TableCell className="text-xs">{pin.full_name || "—"}</TableCell>
                        <TableCell className="text-xs">{pin.operation}</TableCell>
                        <TableCell>
                          <Badge variant={statusVariant(pin.status)}>{pin.status}</Badge>
                        </TableCell>
                        <TableCell className="text-xs">{formatDuration(pin.duration_ms)}</TableCell>
                        <TableCell className="text-xs">{pin.error_message || "—"}</TableCell>
                      </TableRow>
                    )) : (
                      <TableRow>
                        <TableCell colSpan={6} className="text-center py-8 text-sm text-muted-foreground">
                          Aucun détail pin disponible pour ce batch.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}

import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getTvObservabilityProofEvents, getTvObservabilityProofStats } from "@/api/tv";
import type { TvObservabilityProofStatsResponse } from "@/api/types";

function toUtcIso(localValue: string): string | undefined {
  const v = String(localValue || "").trim();
  if (!v) return undefined;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return undefined;
  return d.toISOString();
}

function formatUtc(ts?: string | null): string {
  if (!ts) return "-";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  return d.toLocaleString();
}

export default function TvProofStatsPage() {
  const [screenId, setScreenId] = useState("");
  const [fromLocal, setFromLocal] = useState("");
  const [toLocal, setToLocal] = useState("");
  const [bucket, setBucket] = useState<"HOUR" | "DAY">("HOUR");

  const [stats, setStats] = useState<TvObservabilityProofStatsResponse | null>(null);
  const [rows, setRows] = useState<Array<Record<string, any>>>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const sid = Number(screenId || 0);
      const fromUtc = toUtcIso(fromLocal);
      const toUtc = toUtcIso(toLocal);
      const [s, e] = await Promise.all([
        getTvObservabilityProofStats({
          screenId: sid > 0 ? sid : undefined,
          fromUtc,
          toUtc,
          bucket,
        }),
        getTvObservabilityProofEvents({
          screenId: sid > 0 ? sid : undefined,
          fromUtc,
          toUtc,
          limit: 200,
          offset: 0,
        }),
      ]);
      setStats(s);
      setRows(e.rows || []);
      setTotal(Number(e.total || 0));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStats(null);
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [screenId, fromLocal, toLocal, bucket]);

  useEffect(() => {
    void load();
  }, [load]);

  const topScreens = useMemo(() => stats?.topScreens || [], [stats]);
  const topAssets = useMemo(() => stats?.topAssets || [], [stats]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">TV Proof / Stats</h1>
        <Button variant="outline" disabled={loading} onClick={() => void load()}>
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} /> Refresh
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Load Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader><CardTitle className="text-sm">Filters (UTC Query, Local Display)</CardTitle></CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-5 gap-3">
          <Input value={screenId} onChange={(e) => setScreenId(e.target.value)} placeholder="Screen ID (optional)" />
          <Input type="datetime-local" value={fromLocal} onChange={(e) => setFromLocal(e.target.value)} />
          <Input type="datetime-local" value={toLocal} onChange={(e) => setToLocal(e.target.value)} />
          <Select value={bucket} onValueChange={(v) => setBucket(v as "HOUR" | "DAY")}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="HOUR">HOUR</SelectItem>
              <SelectItem value="DAY">DAY</SelectItem>
            </SelectContent>
          </Select>
          <div className="flex items-center text-sm text-muted-foreground">Events: {total}</div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <Card>
          <CardHeader><CardTitle className="text-sm">Total Proof</CardTitle></CardHeader>
          <CardContent className="text-2xl font-semibold">{stats?.totalProofEvents ?? 0}</CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Status Counts</CardTitle></CardHeader>
          <CardContent className="flex flex-wrap gap-2 text-xs">
            {Object.entries(stats?.statusCounts || {}).map(([k, v]) => <Badge key={k} variant="outline">{k}: {v}</Badge>)}
            {Object.keys(stats?.statusCounts || {}).length === 0 && <span className="text-muted-foreground">No data</span>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Timeline Counts</CardTitle></CardHeader>
          <CardContent className="flex flex-wrap gap-2 text-xs">
            {Object.entries(stats?.timelineCounts || {}).map(([k, v]) => <Badge key={k} variant="outline">{k}: {v}</Badge>)}
            {Object.keys(stats?.timelineCounts || {}).length === 0 && <span className="text-muted-foreground">No data</span>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Series Buckets</CardTitle></CardHeader>
          <CardContent className="text-xs text-muted-foreground">{(stats?.series || []).length} buckets</CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Card>
          <CardHeader><CardTitle className="text-sm">Top Screens</CardTitle></CardHeader>
          <CardContent className="space-y-1 text-xs">
            {topScreens.length === 0 && <div className="text-muted-foreground">No data</div>}
            {topScreens.map((row) => (
              <div key={`${row.screenId}`} className="flex justify-between border-b pb-1">
                <span>Screen #{row.screenId}</span>
                <strong>{row.count}</strong>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Top Assets</CardTitle></CardHeader>
          <CardContent className="space-y-1 text-xs">
            {topAssets.length === 0 && <div className="text-muted-foreground">No data</div>}
            {topAssets.map((row) => (
              <div key={`${row.mediaAssetId}`} className="flex justify-between border-b pb-1">
                <span>{row.mediaAssetId}</span>
                <strong>{row.count}</strong>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-sm">Raw Proof Events</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>UTC Time</TableHead>
                <TableHead>Screen</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Timeline</TableHead>
                <TableHead>Asset</TableHead>
                <TableHead>Snapshot</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => (
                <TableRow key={String(row.id)}>
                  <TableCell className="text-xs">{formatUtc(String(row.proof_at_utc || ""))}</TableCell>
                  <TableCell className="text-xs">{String(row.screen_id || "-")}</TableCell>
                  <TableCell className="text-xs">{String(row.status || "-")}</TableCell>
                  <TableCell className="text-xs">{String(row.proof_type || "-")}</TableCell>
                  <TableCell className="text-xs">{String(row.timeline_type || "-")}</TableCell>
                  <TableCell className="text-xs">{String(row.media_asset_id || "-")}</TableCell>
                  <TableCell className="text-xs">{String(row.snapshot_version || "-")}</TableCell>
                </TableRow>
              ))}
              {rows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-sm text-muted-foreground">No proof events.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

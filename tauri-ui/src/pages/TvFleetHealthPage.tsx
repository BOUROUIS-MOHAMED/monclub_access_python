import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getTvObservabilityFleetHealth } from "@/api/tv";
import type { TvObservabilityFleetRow } from "@/api/types";

function healthBadge(state: string): "success" | "warning" | "destructive" | "secondary" {
  const s = String(state || "").toUpperCase();
  if (s === "HEALTHY") return "success";
  if (s === "WARNING" || s === "DEGRADED") return "warning";
  if (s === "OFFLINE" || s === "UNKNOWN") return "secondary";
  return "destructive";
}

function ageLabel(sec?: number | null): string {
  if (sec == null || !Number.isFinite(sec)) return "-";
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export default function TvFleetHealthPage() {
  const [rows, setRows] = useState<TvObservabilityFleetRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [q, setQ] = useState("");
  const [health, setHealth] = useState("ALL");
  const [runtimeState, setRuntimeState] = useState("ALL");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getTvObservabilityFleetHealth({
        q: q.trim() || undefined,
        health: health === "ALL" ? undefined : health,
        runtimeState: runtimeState === "ALL" ? undefined : runtimeState,
        limit: 500,
        offset: 0,
      });
      setRows(res.rows || []);
      setTotal(Number(res.total || 0));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [q, health, runtimeState]);

  useEffect(() => {
    void load();
  }, [load]);

  const healthCounts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const row of rows) {
      const key = String(row.health || "UNKNOWN").toUpperCase();
      out[key] = (out[key] || 0) + 1;
    }
    return out;
  }, [rows]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">TV Fleet Health</h1>
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
        <CardHeader>
          <CardTitle className="text-sm">Fleet Filters</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search screen/monitor/runtime" />
          <Select value={health} onValueChange={setHealth}>
            <SelectTrigger><SelectValue placeholder="Health" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="ALL">All Health</SelectItem>
              <SelectItem value="HEALTHY">HEALTHY</SelectItem>
              <SelectItem value="WARNING">WARNING</SelectItem>
              <SelectItem value="DEGRADED">DEGRADED</SelectItem>
              <SelectItem value="ERROR">ERROR</SelectItem>
              <SelectItem value="OFFLINE">OFFLINE</SelectItem>
              <SelectItem value="UNKNOWN">UNKNOWN</SelectItem>
            </SelectContent>
          </Select>
          <Select value={runtimeState} onValueChange={setRuntimeState}>
            <SelectTrigger><SelectValue placeholder="Runtime" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="ALL">All Runtime</SelectItem>
              <SelectItem value="RUNNING">RUNNING</SelectItem>
              <SelectItem value="STARTING">STARTING</SelectItem>
              <SelectItem value="STOPPING">STOPPING</SelectItem>
              <SelectItem value="STOPPED">STOPPED</SelectItem>
              <SelectItem value="CRASHED">CRASHED</SelectItem>
              <SelectItem value="ERROR">ERROR</SelectItem>
            </SelectContent>
          </Select>
          <div className="flex items-center text-sm text-muted-foreground">Rows: {total}</div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Health Buckets</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2 text-xs">
          {Object.keys(healthCounts).length === 0 && <span className="text-muted-foreground">No data</span>}
          {Object.entries(healthCounts).map(([key, val]) => (
            <Badge key={key} variant={healthBadge(key)}>{key}: {val}</Badge>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Screens</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Screen</TableHead>
                <TableHead>Health</TableHead>
                <TableHead>Runtime</TableHead>
                <TableHead>Readiness</TableHead>
                <TableHead>Snapshots</TableHead>
                <TableHead>Heartbeat</TableHead>
                <TableHead>Proof</TableHead>
                <TableHead>Issues</TableHead>
                <TableHead>Diagnostics</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => (
                <TableRow key={`${row.screenId}-${row.bindingId || 0}`}>
                  <TableCell>
                    <div className="font-medium">#{row.screenId}</div>
                    <div className="text-xs text-muted-foreground">{row.screenName || "-"}</div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={healthBadge(String(row.health || "UNKNOWN"))}>{String(row.health || "UNKNOWN")}</Badge>
                  </TableCell>
                  <TableCell className="text-xs">{row.runtimeState || "-"}</TableCell>
                  <TableCell className="text-xs">{row.readinessState || "-"}</TableCell>
                  <TableCell className="text-xs">
                    L:{row.latestSnapshotVersion ?? "-"} / LR:{row.latestReadySnapshotVersion ?? "-"} / A:{row.activeSnapshotVersion ?? "-"}
                  </TableCell>
                  <TableCell className="text-xs">{ageLabel(row.heartbeatAgeSec)}</TableCell>
                  <TableCell className="text-xs">{row.proofExpected ? ageLabel(row.proofAgeSec) : "N/A"}</TableCell>
                  <TableCell className="text-xs max-w-[280px] truncate" title={(row.healthReasons || []).join("; ")}>{(row.healthReasons || ["-"])[0] || "-"}</TableCell>
                  <TableCell>
                    <Link className="text-xs text-primary underline" to={`/tv/screens/${encodeURIComponent(String(row.screenId))}/diagnostics`}>
                      Open
                    </Link>
                  </TableCell>
                </TableRow>
              ))}
              {rows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={9} className="text-center text-sm text-muted-foreground">No screens matched the filters.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
